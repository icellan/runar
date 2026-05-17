import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.ANF.Typed
import RunarVerification.Stack.NumEncoding
import RunarVerification.Crypto.HashBackend
import RunarVerification.Crypto.Secp256k1
import RunarVerification.Crypto.NistEC

/-!
# ANF IR — Big-step evaluation (skeleton)

A starter executable big-step semantics for ANF programs.

**Scope of this module (Phase 1 / Phase 2 only).** Per the spec, this
file lays down the dispatch shape and fills in the executable
non-cryptographic constructors. Hashes, EC primitives, and ECDSA /
Rabin / WOTS / SLH-DSA verifiers are introduced as explicit assumptions
or backend-parametric definitions in the dedicated `Crypto` namespace at
the bottom of this file. Each assumption is documented with its role and
where it sits in the larger Phase 3 plan.

**What is concrete here:**

* `loadParam`, `loadProp`, `loadConst` (`int`, `bool`, `bytes`,
  `refAlias`, `thisRef`)
* arithmetic / comparison `bin_op`s on `bigint`
* bytewise `&`, `|`, `^`, and `~` over equal-length byte strings
* byte-equality and short-circuit `&&` / `||`
* `unary_op` (`!`, `~`, `-`)
* `assert` (script aborts iff value is `false`)
* `update_prop` (writes the property slot)
* the four control-flow / framework intrinsics: `super` (no-op in eval),
  `cat` (byte concatenation), `len`, `bool` (coercion), `assert`.
* numeric helper intrinsics: `abs`, `min`, `max`, and `within`.
* byte-string conversion/slicing intrinsics: `bin2num`, `num2bin`,
  `int2str`, `substr`, `left`, `right`, `reverseBytes`,
  `toByteString`, `pack`, `unpack`.
* BIP-143 preimage field extractors over the concrete serialized layout.
* compound output-construction helpers (Tier B11): concrete `def`s for
  `extractOutputHash`, `buildChangeOutput`, `computeStateOutput`,
  and `super`, dispatched through `callBuiltin?`.

**What is axiomatized:**

* the external hash backend for `sha256` / `ripemd160`, plus
  `sha256Compress`, `sha256Finalize`, and `blake3*`
* every EC primitive (secp256k1, P-256, P-384, BN254-G1)
* every signature verifier (ECDSA, Rabin, WOTS+, SLH-DSA-SHA2-{128,192,256}{s,f})
* every field-arithmetic primitive (BabyBear, KoalaBear, BN254-Fp)
* the external preimage-validation backend for `checkPreimage`
* the external authentication backend for `checkSig` / `checkMultiSig`

The axioms are **not** proved sound here. Each is documented with the
property the verification lead should later refine into a proper
specification.

Run `lake exe goldenEval` once that executable is added to drive
this evaluator against the conformance fixtures. The compound
framework intrinsics `computeStateOutput`, `buildChangeOutput`,
`extractOutputHash`, and `super` are now concrete `def`s in
`Crypto` (Tier B11) and dispatched through `callBuiltin?`.
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

private def bitwiseBytesBin (name : String) (f : UInt8 → UInt8 → UInt8)
    (l r : Value) : EvalResult Value :=
  match l.asBytes?, r.asBytes? with
  | some lb, some rb =>
      match RunarVerification.Stack.zipBytesWith? f lb rb with
      | some out => return .vBytes out
      | none => .error (.typeError s!"{name} expects equal-length byte values")
  | _, _ => .error (.typeError s!"{name} expects byte values")

private def invertBytesValue (operand : Value) : EvalResult Value :=
  match operand.asBytes? with
  | some bs =>
      return .vBytes (ByteArray.mk ((bs.toList.map (fun b => ~~~ b)).toArray))
  | none => .error (.typeError "unary_op ~ expects byte value")

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
      -- `result_type: "bytes"` — see 04-anf-lower.ts:204.
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
  | "&", _, _ => bitwiseBytesBin "bin_op &" (· &&& ·) l r
  | "|", _, _ => bitwiseBytesBin "bin_op |" (· ||| ·) l r
  | "^", _, _ => bitwiseBytesBin "bin_op ^" (· ^^^ ·) l r
  | "<<", .vBigint a, .vBigint b => return .vBigint (a * (2 ^ b.toNat))
  | ">>", .vBigint a, .vBigint b => return .vBigint (a / (2 ^ b.toNat))
  | _, _, _ => .error (.unsupported s!"bin_op {op} on these operand types")

def evalUnaryOp (op : String) (operand : Value) (_resultType : Option String) :
    EvalResult Value := do
  match op, operand with
  | "!", .vBool b   => return .vBool (!b)
  | "-", .vBigint i => return .vBigint (-i)
  | "~", _ => invertBytesValue operand
  | _, _ => .error (.unsupported s!"unary_op {op}")

/-! ## Cryptographic primitives — assumptions

Each axiom takes opaque `ByteArray` payloads and returns a deterministic
`ByteArray` (or `Bool`). Determinism is implicit (axioms are total
functions). SHA-256 and RIPEMD-160 are external consensus primitives:
Lean proofs quantify over a hash backend, while the Runar implementations
are tested against independent reference algorithms outside Lean.
Soundness specifications for the remaining primitives are deferred to
Phase 3.
-/

namespace Crypto

-- Hashes
-- SHA-256 and RIPEMD-160 are supplied by the execution environment. The
-- Lean model is parametric in these functions instead of carrying fake
-- executable defaults or attempting to prove the algorithms themselves.
structure HashBackend where
  sha256 : ByteArray → ByteArray
  ripemd160 : ByteArray → ByteArray

private def missingHashBackend (name : String) (_ : ByteArray) : ByteArray :=
  panic! s!"external {name} hash backend required for Lean execution"

private def executableHashBackend : HashBackend where
  sha256 := missingHashBackend "sha256"
  ripemd160 := missingHashBackend "ripemd160"

@[implemented_by executableHashBackend]
axiom hashBackend : HashBackend

def sha256 (b : ByteArray) : ByteArray := hashBackend.sha256 b
def ripemd160 (b : ByteArray) : ByteArray := hashBackend.ripemd160 b
/-- `OP_HASH160` consensus definition: RIPEMD-160 ∘ SHA-256.
Concrete `def` (Tier 5.3, 2026-05-10): composes the two backend hashes.
The linking lemma `hash160_eq_ripemd160_sha256` in `Crypto/Spec.lean`
is now provable by `rfl`. -/
def hash160 (b : ByteArray) : ByteArray := ripemd160 (sha256 b)
/-- `OP_HASH256` consensus definition: SHA-256 ∘ SHA-256.
Concrete `def` (Tier 5.3, 2026-05-10): composes the backend SHA-256
with itself. The linking lemma `hash256_eq_double_sha256` in
`Crypto/Spec.lean` is now provable by `rfl`. -/
def hash256 (b : ByteArray) : ByteArray := sha256 (sha256 b)
axiom sha256Compress  : ByteArray → ByteArray → ByteArray
axiom sha256Finalize  : ByteArray → ByteArray → Int → ByteArray
/-- BLAKE3 single-block compression (concrete `def`, Tier B3-a, 2026-05-17).
Delegates to `RunarVerification.Crypto.HashBackend.Blake3.blake3Compress`,
the closed-form spec mirroring BLAKE3 §2.1 and
`packages/runar-compiler/src/passes/blake3-codegen.ts`. -/
def blake3Compress (cv : ByteArray) (block : ByteArray) : ByteArray :=
  RunarVerification.Crypto.HashBackend.Blake3.blake3Compress cv block
/-- BLAKE3 single-block hash entry (concrete `def`, Tier B3-a, 2026-05-17).
Delegates to `RunarVerification.Crypto.HashBackend.Blake3.blake3Hash`,
which zero-pads the input to 64 bytes and runs the compression with the
BLAKE3 IV as chaining value and flags `CHUNK_START | CHUNK_END | ROOT`. -/
def blake3Hash (msg : ByteArray) : ByteArray :=
  RunarVerification.Crypto.HashBackend.Blake3.blake3Hash msg

-- secp256k1 EC primitives (operands are 64-byte uncompressed points,
-- byte layout `x[32] || y[32]` big-endian unsigned per
-- `packages/runar-lang/src/ec.ts`).
--
-- Phase B4-a (2026-05-17): the 10 bare `ec*` axioms have been replaced
-- by concrete `def`s delegating to
-- `RunarVerification.Crypto.Secp256k1`, the closed-form spec mirroring
-- SEC 2 v2 secp256k1 parameters and
-- `packages/runar-compiler/src/passes/ec-codegen.ts`. This unblocks
-- the §5.29 group-law audit (the 10 group-law axioms in
-- `Crypto/Spec.lean §1` become derivable once these defs land).
/-- secp256k1 point addition (concrete `def`, Tier B4-a, 2026-05-17). -/
def ecAdd (p q : ByteArray) : ByteArray :=
  RunarVerification.Crypto.Secp256k1.ecAdd p q
/-- secp256k1 scalar multiplication `k · P` (concrete `def`, Tier B4-a). -/
def ecMul (p : ByteArray) (k : Int) : ByteArray :=
  RunarVerification.Crypto.Secp256k1.ecMul p k
/-- secp256k1 scalar multiplication of the generator `G` by `k`
(concrete `def`, Tier B4-a). -/
def ecMulGen (k : Int) : ByteArray :=
  RunarVerification.Crypto.Secp256k1.ecMulGen k
/-- secp256k1 point negation `(x, p − y mod p)` (concrete `def`, Tier B4-a). -/
def ecNegate (p : ByteArray) : ByteArray :=
  RunarVerification.Crypto.Secp256k1.ecNegate p
/-- secp256k1 on-curve check `y² ≡ x³ + 7 (mod p)` (concrete `def`, Tier B4-a). -/
def ecOnCurve (p : ByteArray) : Bool :=
  RunarVerification.Crypto.Secp256k1.ecOnCurve p
/-- Signed-aware modular reduction `((a mod m) + m) mod m` (concrete `def`,
Tier B4-a). -/
def ecModReduce (a m : Int) : Int :=
  RunarVerification.Crypto.Secp256k1.ecModReduce a m
/-- secp256k1 SEC-compressed encoding (33-byte `parity ++ x_be32`)
(concrete `def`, Tier B4-a). -/
def ecEncodeCompressed (p : ByteArray) : ByteArray :=
  RunarVerification.Crypto.Secp256k1.ecEncodeCompressed p
/-- Pack `(x, y)` integers as a 64-byte big-endian point
(concrete `def`, Tier B4-a). -/
def ecMakePoint (x y : Int) : ByteArray :=
  RunarVerification.Crypto.Secp256k1.ecMakePoint x y
/-- Extract x-coordinate from a 64-byte point (concrete `def`, Tier B4-a). -/
def ecPointX (p : ByteArray) : Int :=
  RunarVerification.Crypto.Secp256k1.ecPointX p
/-- Extract y-coordinate from a 64-byte point (concrete `def`, Tier B4-a). -/
def ecPointY (p : ByteArray) : Int :=
  RunarVerification.Crypto.Secp256k1.ecPointY p

/-! ### NIST P-256 / P-384 (concrete `def`s, Tier B5-a, 2026-05-17)

The twelve P-256 / P-384 primitives — point addition, scalar
multiplication, generator multiplication, curve-membership test,
compressed encoding, and ECDSA verification — are concrete `def`s
delegating to `RunarVerification.Crypto.NistEC.{cAdd, cMul, cMulGen,
cOnCurve, cEncodeCompressed, cVerifyECDSA}`. The spec there mirrors
FIPS 186-5 §6.4 (ECDSA) and Appendix D.1.2.3 / D.1.2.4 (curve
parameters), composed against the SHA-256 backend defined just
above for `verifyECDSA_*`. The codegen-to-spec linking theorems
`emitP256*_runOps_eq` / `emitP384*_runOps_eq` in
`Stack/P256P384.lean` remain axioms at the B5-a tier; B5 (Phase 3
post-Tier 1) discharges them against the concrete spec defs landed
here. -/

-- NIST P-256
def p256Add (a b : ByteArray) : ByteArray :=
  RunarVerification.Crypto.NistEC.cAdd
    RunarVerification.Crypto.NistEC.p256Params a b
def p256Mul (a : ByteArray) (k : Int) : ByteArray :=
  RunarVerification.Crypto.NistEC.cMul
    RunarVerification.Crypto.NistEC.p256Params a k
def p256MulGen (k : Int) : ByteArray :=
  RunarVerification.Crypto.NistEC.cMulGen
    RunarVerification.Crypto.NistEC.p256Params k
def p256OnCurve (a : ByteArray) : Bool :=
  RunarVerification.Crypto.NistEC.cOnCurve
    RunarVerification.Crypto.NistEC.p256Params a
def p256EncodeCompressed (a : ByteArray) : ByteArray :=
  RunarVerification.Crypto.NistEC.cEncodeCompressed
    RunarVerification.Crypto.NistEC.p256Params a
def verifyECDSA_P256 (sig pubkey preimage : ByteArray) : Bool :=
  RunarVerification.Crypto.NistEC.cVerifyECDSA
    RunarVerification.Crypto.NistEC.p256Params sha256 sig pubkey preimage

-- NIST P-384
def p384Add (a b : ByteArray) : ByteArray :=
  RunarVerification.Crypto.NistEC.cAdd
    RunarVerification.Crypto.NistEC.p384Params a b
def p384Mul (a : ByteArray) (k : Int) : ByteArray :=
  RunarVerification.Crypto.NistEC.cMul
    RunarVerification.Crypto.NistEC.p384Params a k
def p384MulGen (k : Int) : ByteArray :=
  RunarVerification.Crypto.NistEC.cMulGen
    RunarVerification.Crypto.NistEC.p384Params k
def p384OnCurve (a : ByteArray) : Bool :=
  RunarVerification.Crypto.NistEC.cOnCurve
    RunarVerification.Crypto.NistEC.p384Params a
def p384EncodeCompressed (a : ByteArray) : ByteArray :=
  RunarVerification.Crypto.NistEC.cEncodeCompressed
    RunarVerification.Crypto.NistEC.p384Params a
def verifyECDSA_P384 (sig pubkey preimage : ByteArray) : Bool :=
  RunarVerification.Crypto.NistEC.cVerifyECDSA
    RunarVerification.Crypto.NistEC.p384Params sha256 sig pubkey preimage

-- BabyBear / KoalaBear field arithmetic.
--
-- Phase B6 (2026-05-17): the four bare axioms `bbFieldAdd / Sub / Mul / Inv`
-- have been replaced by concrete `def`s over the canonical BabyBear modulus
-- `p = 2^31 - 2^27 + 1 = 2013265921`. Per project policy (CLAUDE.md
-- "EVM/STARK proof-system primitives are Go-only"), BabyBear codegen ships
-- in the Go tier only, but the Lean ANF evaluator still needs a meaning for
-- these symbols so that downstream theorems quoting them ground in
-- closed-form computation rather than opaque assumptions.
--
-- The formulas mirror `Crypto/Spec.lean` §8 (`bbAdd / Sub / Mul / Inv`) and
-- the TS / Go reference (`compilers/go/codegen/babybear.go` →
-- `packages/runar-compiler/src/passes/babybear-codegen.ts`). The companion
-- theorems `bbFieldAdd_correct / Sub_correct / Mul_correct / Inv_correct`
-- in `Crypto/Spec.lean` §8.3 are now provable by reduction (was: axioms).
def bbFieldPrime : Int := 2013265921

def bbFieldMod (a : Int) : Int :=
  ((a % bbFieldPrime) + bbFieldPrime) % bbFieldPrime

def bbFieldAdd (a b : Int) : Int := bbFieldMod (a + b)
def bbFieldSub (a b : Int) : Int := bbFieldMod (a - b)
def bbFieldMul (a b : Int) : Int := bbFieldMod (a * b)

/-- Modular exponentiation by a non-negative `Nat` exponent. Used by the
Fermat-little-theorem inverse below. Recursive on the exponent. -/
def bbFieldPowNat (a : Int) : Nat → Int
  | 0     => 1
  | n + 1 => bbFieldMul a (bbFieldPowNat a n)

/-- `bbFieldInv a = a^(p-2) mod p`. Closed-form Fermat-little-theorem
expression. Note: `bbFieldInv 0 = 0^(p-2) = 0`, which matches the codegen
behaviour (`Stack/BabyBear.lean#fieldInv` does not special-case `a = 0`). -/
def bbFieldInv (a : Int) : Int :=
  bbFieldPowNat (bbFieldMod a) (bbFieldPrime - 2).toNat

-- Merkle / Rabin / Post-quantum

/-! ### Merkle path verifier — concrete helpers (Path 2, 2026-05-17)

`merkleRootSha256` / `merkleRootHash256` are now concrete `def`s
delegating to the path-verifier kernel `merkleVerifyPath` defined
just below. The kernel is duplicated here (rather than imported
from `Crypto/Spec.lean`) because `Crypto/Spec.lean` already imports
`ANF/Eval.lean` — taking the opposite dependency would cycle. The
definitions are byte-identical to `Crypto.Spec.merkleVerifyStep` /
`Crypto.Spec.merkleVerifyPathFrom` / `Crypto.Spec.merkleVerifyPath`
(see `Crypto/Spec.lean` §7). -/

/-- One level of the Merkle path verifier. Given the running
`current` hash, the remaining `proof` bytes, the `index`, and the
current `level`, extract the next 32-byte sibling, compute the
direction bit `(index >> level) & 1`, concatenate sibling and
running hash in the right order, and hash via `h`. Returns the new
`current` and the rest of the proof. -/
def merkleVerifyStep (h : ByteArray → ByteArray)
    (current : ByteArray) (proof : ByteArray) (index : Int) (level : Nat) :
    ByteArray × ByteArray :=
  let sibling := proof.extract 0 32
  let rest    := proof.extract 32 proof.size
  let shifted : Nat := index.natAbs / (2 ^ level)
  let dir     : Nat := shifted % 2
  let combined : ByteArray :=
    if dir = 0 then current ++ sibling
              else sibling ++ current
  (h combined, rest)

/-- Climb `d` levels from `leaf` starting at `startLevel`, using
`proof` for sibling hashes and `index` for direction bits. -/
def merkleVerifyPathFrom (h : ByteArray → ByteArray)
    (leaf : ByteArray) (proof : ByteArray) (index : Int)
    (startLevel : Nat) : Nat → ByteArray
  | 0     => leaf
  | d + 1 =>
      let (current', proof') := merkleVerifyStep h leaf proof index startLevel
      merkleVerifyPathFrom h current' proof' index (startLevel + 1) d

/-- Top-level entry: climb the full `d`-level path starting from level 0. -/
def merkleVerifyPath (h : ByteArray → ByteArray)
    (leaf : ByteArray) (proof : ByteArray) (index : Int) (d : Nat) : ByteArray :=
  merkleVerifyPathFrom h leaf proof index 0 d

/-- `merkleRootSha256(leaf, proof, index, depth)` — Merkle root via
single-SHA-256 hash function, depth supplied as `Int` from the
compile-time integer literal. Negative depth is treated as zero
via `Int.toNat`. -/
def merkleRootSha256 (leaf proof : ByteArray) (index depth : Int) : ByteArray :=
  merkleVerifyPath sha256 leaf proof index depth.toNat

/-- `merkleRootHash256(leaf, proof, index, depth)` — same as
`merkleRootSha256` but with the double-SHA-256 (HASH256) hash
function. -/
def merkleRootHash256 (leaf proof : ByteArray) (index depth : Int) : ByteArray :=
  merkleVerifyPath hash256 leaf proof index depth.toNat

/-! ### Rabin signature verifier — concrete `def` (Path 2, 2026-05-17)

`verifyRabinSig` is converted from a bare 4-`ByteArray` axiom to a
concrete `def` that decodes the script-number operands (`sig`,
`padding`, `pubKey`) via `Stack.decodeMinimalLE` and forwards to
the closed-form modular identity used by `Crypto.Spec.verifyRabinSig_spec`:

  `(sig * sig + padding) mod pubKey  ==  decodeMinimalLE (sha256 msg)`

The same modular-identity body is duplicated here (instead of
imported from `Crypto/Spec.lean`) for the same reason as the
merkle helpers above. The two functions agree pointwise; codegen
soundness is proved via the Spec form in `Stack/Rabin.lean`. -/
def verifyRabinSig (msg sig padding pubKey : ByteArray) : Bool :=
  let sigI     := RunarVerification.Stack.decodeMinimalLE sig
  let padI     := RunarVerification.Stack.decodeMinimalLE padding
  let pubI     := RunarVerification.Stack.decodeMinimalLE pubKey
  let lhs      := (sigI * sigI + padI) % pubI
  decide ((RunarVerification.Stack.encodeMinimalLE lhs).toList = (sha256 msg).toList)
axiom verifyWOTS              : ByteArray → ByteArray → ByteArray → Bool

/-! ### SLH-DSA-SHA2 verifier — concrete `def`s (Path 2 B9-a, 2026-05-17)

`verifySLHDSA_SHA2_<param>` for the 6 FIPS 205 SHA-2 parameter sets
(`128s`, `128f`, `192s`, `192f`, `256s`, `256f`) are converted from
bare 3-`ByteArray` axioms to concrete `def`s that compose SHA-256
(`Crypto.sha256`), an MGF1-style counter expansion (FIPS 205 §11.2.1),
the WOTS+ chain function, the FORS leaf-and-auth-path walk, and the
hypertree's `d` XMSS layers, exactly per FIPS 205 §10.2 `slh_verify`.

The algorithm is parametric in a `SlhDsaParams` record carrying the
8 FIPS 205 SHA-2 parameters (`n, h, d, hp, a, k, len`); each of the 6
top-level wrappers fixes its own parameter record and delegates to
the parametric implementation `slhDsaVerifyImpl`. Companion specs in
`Crypto/Spec.lean` §11 (`verifySlhDsa_SHA2_*`) are byte-identical and
contribute zero additional axioms.

The verifier is total: malformed inputs (short signatures, wrong
pubkey length) yield a `false` result via empty / zero defaults from
`ByteArray.extract` / `byteAt`, mirroring the on-chain behaviour of
the codegen, which would simply fail the final `OP_EQUAL` comparison.

Mirrors `EmitVerifySLHDSA` /  `emitSLHFors` / `emitSLHWotsAll` /
`emitSLHMerkle` /  `emitSLHHmsg` in
`compilers/go/codegen/slh_dsa.go` (the Go reference) and
`packages/runar-compiler/src/passes/slh-dsa-codegen.ts` (the TS
reference). The codegen-to-spec equivalence theorem
`runOps_slhDsaBodyOps_eq` is deferred to a future `Stack/SlhDsa.lean`
patch (currently this `def` grounds the meaning of "SLH-DSA verifies"
in closed-form computation; the on-chain Stack-IR equivalence is the
remaining Tier 3 obligation).
-/

/-- FIPS 205 SHA-2 SLH-DSA parameter record. -/
structure SlhDsaParams where
  /-- Security parameter (hash output bytes): 16, 24, or 32. -/
  n : Nat
  /-- Total hypertree height. -/
  h : Nat
  /-- Hypertree layer count. -/
  d : Nat
  /-- Single-XMSS subtree height (`h / d`). -/
  hp : Nat
  /-- FORS tree height. -/
  a : Nat
  /-- FORS tree count. -/
  k : Nat
  /-- WOTS+ chain count (`len1 + len2`). -/
  len : Nat
  /-- WOTS+ message-chain count (`2*n`). -/
  len1 : Nat
  /-- WOTS+ checksum-chain count (3 for all SHA-2 sets). -/
  len2 : Nat
  deriving Repr

namespace SlhDsa

/-- Build a `SlhDsaParams` record from the 5 free FIPS 205 SHA-2
parameters. `len1 = 2*n`, `len2 = 3` (for all six SHA-2 sets — the
Winternitz `w = 16` choice gives `len2 = ⌊log_16(len1 · 15)⌋ + 1 = 3`
for every `n ∈ {16, 24, 32}`), `hp = h / d`, `len = len1 + len2`. -/
def mkParams (n h d a k : Nat) : SlhDsaParams :=
  let len1 := 2 * n
  { n := n, h := h, d := d, hp := h / d, a := a, k := k,
    len := len1 + 3, len1 := len1, len2 := 3 }

/-- FIPS 205 Table 2 SHA-2 parameter sets. -/
def params128s : SlhDsaParams := mkParams 16 63 7  12 14
def params128f : SlhDsaParams := mkParams 16 66 22 6  33
def params192s : SlhDsaParams := mkParams 24 63 7  14 17
def params192f : SlhDsaParams := mkParams 24 66 22 8  33
def params256s : SlhDsaParams := mkParams 32 64 8  14 22
def params256f : SlhDsaParams := mkParams 32 68 17 8  35

/-- Read byte `i` of `b`, or `0` if out of bounds. -/
@[inline] def byteAt (b : ByteArray) (i : Nat) : Nat :=
  if i < b.size then (b.get! i).toNat else 0

/-- Extract `len` bytes from `b` starting at offset `off`. Returns
empty / zero-padded if out of range. -/
@[inline] def slice (b : ByteArray) (off len : Nat) : ByteArray :=
  b.extract off (off + len)

/-- A `Nat` written big-endian into `width` bytes. Excess high bits are
truncated. -/
def natToBE (v width : Nat) : ByteArray :=
  let rec go (acc : ByteArray) (v : Nat) : Nat → ByteArray
    | 0     => acc
    | k + 1 =>
        let b   : UInt8 := (v % 256).toUInt8
        let acc := ByteArray.mk #[b] ++ acc
        go acc (v / 256) k
  termination_by k => k
  go ByteArray.empty v width

/-- Decode a big-endian byte string into a `Nat`. -/
def beToNat (b : ByteArray) : Nat :=
  let rec go (i acc : Nat) : Nat :=
    if i ≥ b.size then acc
    else go (i + 1) (acc * 256 + (b.get! i).toNat)
  termination_by b.size - i
  go 0 0

/-- Modulus over `2 ^ k`. Used by digest splits (`treeIdx` /
`leafIdx`) and by `idx mod 2^a` in the FORS tree walk. -/
@[inline] def modPow2 (v k : Nat) : Nat := v % (Nat.pow 2 k)

/-- Integer division by `2 ^ k`. -/
@[inline] def divPow2 (v k : Nat) : Nat := v / (Nat.pow 2 k)

/-- 22-byte FIPS 205 compressed ADRS. Layout (per
`compilers/go/codegen/slh_dsa.go:slhADRS`):

  [0]     layer (1 byte)
  [1..8]  tree (8 bytes big-endian)
  [9]     type (1 byte)
  [10..13] keypair (4 bytes big-endian)
  [14..17] chain   (4 bytes big-endian, or treeHeight for tree types)
  [18..21] hash    (4 bytes big-endian, or treeIndex for tree types)

`tree` is a `Nat` (large-tree-index); the other fields are `Nat` ≤ 2³².
-/
def buildAdrs (layer : Nat) (tree : Nat) (adrsTyp : Nat)
    (keypair : Nat) (chain : Nat) (hash : Nat) : ByteArray :=
  let layerB := natToBE layer 1
  let treeB  := natToBE tree 8
  let typB   := natToBE adrsTyp 1
  let kpB    := natToBE keypair 4
  let chB    := natToBE chain 4
  let hsB    := natToBE hash 4
  layerB ++ treeB ++ typB ++ kpB ++ chB ++ hsB

/-- ADRS type constants (FIPS 205 §4). -/
def adrsWotsHash  : Nat := 0
def adrsWotsPk    : Nat := 1
def adrsTree      : Nat := 2
def adrsForsTree  : Nat := 3
def adrsForsRoots : Nat := 4

/-- `pkSeedPad pkSeed` = `pkSeed` right-padded to 64 bytes with zeros.
This is the SHA-2 ADRS-compression padding used by the tweakable hash
`T_ℓ`. -/
def pkSeedPad (pkSeed : ByteArray) (n : Nat) : ByteArray :=
  if n ≥ 64 then pkSeed.extract 0 64
  else pkSeed ++ ByteArray.mk (Array.replicate (64 - n) (0 : UInt8))

/-- FIPS 205 SHA-2 tweakable hash `T_ℓ(pkSeed, ADRS, M) = SHA-256(pkSeedPad
‖ ADRS_compressed ‖ M)` truncated to `n` bytes. The 22-byte
compressed ADRS is used (FIPS 205 §11.2.2). -/
def tHash (pkSeed adrs msg : ByteArray) (n : Nat) : ByteArray :=
  let psp := pkSeedPad pkSeed n
  (sha256 (psp ++ adrs ++ msg)).extract 0 n

/-- FIPS 205 SHA-2 chain function `F = T_1`. Same as `tHash` with the
chain-step's hashAddress-specific ADRS. -/
@[inline] def fHash (pkSeed adrs msg : ByteArray) (n : Nat) : ByteArray :=
  tHash pkSeed adrs msg n

/-- MGF1-SHA-256 counter-mode expansion of `seed` to `outLen` bytes
(FIPS 205 §11.2.1: `Hmsg` block-style expansion). Concatenates
`SHA-256(seed ‖ ctr)` for `ctr = 0, 1, ...` until `outLen` bytes are
produced, then truncates. -/
def mgf1Sha256 (seed : ByteArray) (outLen : Nat) : ByteArray :=
  let rec go (ctr : Nat) (acc : ByteArray) : Nat → ByteArray
    | 0     => acc
    | k + 1 =>
        let ctrBE := natToBE ctr 4
        let block := sha256 (seed ++ ctrBE)
        go (ctr + 1) (acc ++ block) k
  termination_by k => k
  let blocks := (outLen + 31) / 32
  (go 0 ByteArray.empty blocks).extract 0 outLen

/-- `Hmsg(R, pkSeed, pkRoot, msg)` for FIPS 205 SHA-2. The "seed" of
the MGF1 expansion is `SHA-256(R ‖ pkSeed ‖ pkRoot ‖ msg)`. Returns
exactly `outLen` bytes. -/
def hMsg (R pkSeed pkRoot msg : ByteArray) (outLen : Nat) : ByteArray :=
  let seed := sha256 (R ++ pkSeed ++ pkRoot ++ msg)
  mgf1Sha256 seed outLen

/-- WOTS+ chain step: `s` consecutive applications of the chain
function starting from chain index `startJ`. Each step uses
`adrs(chainIdx, j)` with `j` ranging over `[startJ, startJ + s)`. -/
def runChainFrom (pkSeed : ByteArray) (n layer chainIdx : Nat)
    (tree : Nat) (keypair : Nat) :
    (startJ : Nat) → (s : Nat) → (x : ByteArray) → ByteArray
  | _, 0,     x => x
  | startJ, s + 1, x =>
      let adrs := buildAdrs layer tree adrsWotsHash keypair chainIdx startJ
      let x'   := fHash pkSeed adrs x n
      runChainFrom pkSeed n layer chainIdx tree keypair (startJ + 1) s x'

/-- Decompose the i'th WOTS+ message digit from a length-`n` `msgHash`
(`len1 = 2*n` nibble digits). Index `i` is byte `i / 2`'s high nibble
if `i` is even, low nibble if `i` is odd. -/
@[inline] def wotsMsgNibble (msgHash : ByteArray) (i : Nat) : Nat :=
  let b := byteAt msgHash (i / 2)
  if i % 2 = 0 then b / 16 else b % 16

/-- Sum of `(15 - d_i)` over the `len1 = 2*n` message nibbles. -/
def wotsCsum (msgHash : ByteArray) (len1 : Nat) : Nat :=
  let rec go (i acc : Nat) : Nat :=
    if i ≥ len1 then acc
    else go (i + 1) (acc + (15 - wotsMsgNibble msgHash i))
  termination_by len1 - i
  go 0 0

/-- The full 67-or-equivalent WOTS+ digit sequence: `len1` message
nibbles followed by `len2 = 3` checksum digits (high-to-low base-16
digits of `csum`). -/
def wotsDigit (msgHash : ByteArray) (i len1 : Nat) : Nat :=
  if i < len1 then wotsMsgNibble msgHash i
  else
    let csum := wotsCsum msgHash len1
    match i - len1 with
    | 0 => (csum / 256) % 16
    | 1 => (csum / 16) % 16
    | _ => csum % 16

/-- Compute one WOTS+ chain endpoint at chain index `i`, taking
`sigChunk = sig[i·n .. (i+1)·n]` and running the chain function
through steps `[d_i, 15)`. -/
def wotsChainEndpoint (pkSeed sig msgHash : ByteArray)
    (n layer i len1 tree keypair : Nat) : ByteArray :=
  let sigChunk := slice sig (i * n) n
  let d := wotsDigit msgHash i len1
  runChainFrom pkSeed n layer i tree keypair d (15 - d) sigChunk

/-- Concatenate all `len` chain endpoints in order. -/
def wotsConcatEndpoints (pkSeed sig msgHash : ByteArray)
    (n layer len len1 tree keypair : Nat) : ByteArray :=
  let rec go (i : Nat) (acc : ByteArray) : ByteArray :=
    if i ≥ len then acc
    else go (i + 1) (acc ++ wotsChainEndpoint pkSeed sig msgHash
                              n layer i len1 tree keypair)
  termination_by len - i
  go 0 ByteArray.empty

/-- WOTS+ public-key-from-signature: recover the WOTS+ public key by
running each chain to its endpoint then compressing with `T_len`. -/
def wotsPkFromSig (pkSeed wotsSig msgHash : ByteArray)
    (n layer len len1 tree keypair : Nat) : ByteArray :=
  let endpts := wotsConcatEndpoints pkSeed wotsSig msgHash
                  n layer len len1 tree keypair
  let adrs   := buildAdrs layer tree adrsWotsPk keypair 0 0
  tHash pkSeed adrs endpts n

/-- One Merkle authentication-path level. Given the running `node`,
the remaining `auth` bytes, the leaf direction `leafIdx` shifted to
level `j`, the current `tree` index, and per-tree ADRS data, extract
the next `n`-byte sibling, decide left/right via `(leafIdx >> j) % 2`,
concatenate in the right order and tweakable-hash with the
appropriate tree-level ADRS. -/
def xmssAuthStep (pkSeed : ByteArray)
    (n layer : Nat) (tree : Nat) (leafIdx : Nat) (j : Nat)
    (node auth : ByteArray) : ByteArray × ByteArray :=
  let sibling := slice auth 0 n
  let rest    := auth.extract n auth.size
  let bit     : Nat := (leafIdx / (Nat.pow 2 j)) % 2
  let combined := if bit = 0 then node ++ sibling else sibling ++ node
  let hashIdx  := leafIdx / (Nat.pow 2 (j + 1))
  let adrs     := buildAdrs layer tree adrsTree 0 (j + 1) hashIdx
  (tHash pkSeed adrs combined n, rest)

/-- Climb the XMSS Merkle tree for `hp` levels. -/
def xmssAuthClimb (pkSeed : ByteArray)
    (n layer : Nat) (tree : Nat) (leafIdx : Nat) :
    (j : Nat) → (steps : Nat) → (node : ByteArray) → (auth : ByteArray) →
    ByteArray
  | _, 0,         node, _ => node
  | j, steps + 1, node, auth =>
      let (node', auth') := xmssAuthStep pkSeed n layer tree leafIdx j node auth
      xmssAuthClimb pkSeed n layer tree leafIdx (j + 1) steps node' auth'

/-- XMSS public-key-from-signature: recover the XMSS root by computing
the WOTS+ public key (the leaf), then climbing `hp` Merkle auth-path
levels. -/
def xmssPkFromSig (pkSeed wotsSig auth msgHash : ByteArray)
    (n layer hp len len1 tree leafIdx : Nat) : ByteArray :=
  let wpk := wotsPkFromSig pkSeed wotsSig msgHash n layer len len1 tree leafIdx
  xmssAuthClimb pkSeed n layer tree leafIdx 0 hp wpk auth

/-- Extract the i'th FORS index — `a` bits at bit-offset `i*a` from
`md` (big-endian). -/
def forsIndex (md : ByteArray) (i a : Nat) : Nat :=
  let bitStart  := i * a
  let bitsTotal := 8 * md.size
  -- Treat md as a big-endian Nat, shift right to align the requested
  -- `a` bits at the LSB position, then mask.
  let mdNat := beToNat md
  let rightShift := bitsTotal - bitStart - a
  (mdNat / Nat.pow 2 rightShift) % Nat.pow 2 a

/-- One FORS auth-path level. The combiner is structurally identical
to `xmssAuthStep`, but the ADRS uses `adrsForsTree` and the hash
index is `i · 2^(a - j - 1) + (idx >> (j + 1))`. -/
def forsAuthStep (pkSeed : ByteArray)
    (n : Nat) (tree keypair : Nat)
    (i idx j a : Nat)
    (node auth : ByteArray) : ByteArray × ByteArray :=
  let sibling := slice auth 0 n
  let rest    := auth.extract n auth.size
  let bit     : Nat := (idx / Nat.pow 2 j) % 2
  let combined := if bit = 0 then node ++ sibling else sibling ++ node
  let hashIdx  := i * Nat.pow 2 (a - j - 1) + (idx / Nat.pow 2 (j + 1))
  let adrs     := buildAdrs 0 tree adrsForsTree keypair (j + 1) hashIdx
  (tHash pkSeed adrs combined n, rest)

/-- Climb the FORS Merkle subtree for `steps` levels. -/
def forsAuthClimb (pkSeed : ByteArray)
    (n : Nat) (tree keypair : Nat)
    (i idx a : Nat) :
    (j : Nat) → (steps : Nat) → (node : ByteArray) → (auth : ByteArray) →
    ByteArray
  | _, 0,         node, _ => node
  | j, steps + 1, node, auth =>
      let (node', auth') :=
        forsAuthStep pkSeed n tree keypair i idx j a node auth
      forsAuthClimb pkSeed n tree keypair i idx a (j + 1) steps node' auth'

/-- Recover one FORS tree's root from its sub-signature `(sk, auth)`.
The FORS tree's leaf at position `idx` is `T(pkSeed, ADRS_FORS_TREE{
chain=0, hash=i·2^a + idx}, sk)`, then climb `a` levels. -/
def forsTreeRoot (pkSeed forsSubSig : ByteArray)
    (n : Nat) (tree keypair : Nat)
    (i idx a : Nat) : ByteArray :=
  let sk      := slice forsSubSig 0 n
  let auth    := forsSubSig.extract n forsSubSig.size
  let leafIdx := i * Nat.pow 2 a + idx
  let adrs    := buildAdrs 0 tree adrsForsTree keypair 0 leafIdx
  let leaf    := tHash pkSeed adrs sk n
  forsAuthClimb pkSeed n tree keypair i idx a 0 a leaf auth

/-- Concatenate the `k` FORS tree roots, indexing each by the
corresponding `a`-bit slice of `md`. The total FORS sub-signature
length is `k · (1 + a) · n`. -/
def forsRootsConcat (pkSeed forsSig md : ByteArray)
    (n : Nat) (tree keypair : Nat) (a k : Nat) : ByteArray :=
  let subLen := (1 + a) * n
  let rec go (i : Nat) (acc : ByteArray) : ByteArray :=
    if i ≥ k then acc
    else
      let sub := slice forsSig (i * subLen) subLen
      let idx := forsIndex md i a
      go (i + 1) (acc ++ forsTreeRoot pkSeed sub n tree keypair i idx a)
  termination_by k - i
  go 0 ByteArray.empty

/-- FORS public-key-from-signature: concatenate all `k` tree roots and
compress under `T_{k·n}` with ADRS = FORS_ROOTS. -/
def forsPkFromSig (pkSeed forsSig md : ByteArray)
    (n : Nat) (tree keypair : Nat) (a k : Nat) : ByteArray :=
  let rootsCat := forsRootsConcat pkSeed forsSig md n tree keypair a k
  let adrs     := buildAdrs 0 tree adrsForsRoots keypair 0 0
  tHash pkSeed adrs rootsCat n

/-- One hypertree XMSS layer. Recovers the layer's root from the
current `node`, the layer's XMSS signature `xmssSig` (WOTS+ sig
followed by Merkle auth path), the current `tree` and `leafIdx`.
Also updates `tree` and `leafIdx` for the next layer:
`leafIdx_next = treeIdx % 2^hp`, `treeIdx_next = treeIdx >> hp`,
keypair = leafIdx. -/
def htLayer (pkSeed xmssSig node : ByteArray)
    (n hp len len1 : Nat) (layer : Nat) (tree leafIdx : Nat) :
    ByteArray :=
  let wotsLen := len * n
  let wotsSig := slice xmssSig 0 wotsLen
  let auth    := xmssSig.extract wotsLen xmssSig.size
  xmssPkFromSig pkSeed wotsSig auth node n layer hp len len1 tree leafIdx

/-- Climb the hypertree for `d` XMSS layers. At each step, peel off
the next XMSS sub-signature from `htSig`, recover the layer's root,
then update `tree` (>> hp) and `leafIdx` (mod 2^hp) for the next
layer. -/
def htClimb (pkSeed : ByteArray)
    (n hp len len1 : Nat) :
    (layer : Nat) → (steps : Nat) → (tree leafIdx : Nat) →
    (node htSig : ByteArray) → ByteArray
  | _, 0,         _, _, node, _ => node
  | layer, steps + 1, tree, leafIdx, node, htSig =>
      let xmssLen := (len + hp) * n
      let xmssSig := slice htSig 0 xmssLen
      let rest    := htSig.extract xmssLen htSig.size
      let node'   := htLayer pkSeed xmssSig node n hp len len1 layer tree leafIdx
      let leafIdx' := tree % Nat.pow 2 hp
      let tree'    := tree / Nat.pow 2 hp
      htClimb pkSeed n hp len len1 (layer + 1) steps tree' leafIdx'
              node' rest

/-- FIPS 205 SHA-2 SLH-DSA full verification algorithm, parametric in
a `SlhDsaParams` record.

Inputs: `msg`, `sig`, `pk`. The verifier:

1. Parses `pk = pkSeed(n) ‖ pkRoot(n)`.
2. Parses `sig = R(n) ‖ forsSig(k·(1+a)·n) ‖ htSig(d·(len+hp)·n)`.
3. Computes `digest = Hmsg(R, pkSeed, pkRoot, msg) → md ‖ treeIdx ‖ leafIdx`.
4. Computes `forsPk = forsPkFromSig(forsSig, md, ...)`.
5. Climbs `d` hypertree layers via `htClimb` to recover `root`.
6. Returns `root == pkRoot`.

Returns `false` for malformed inputs (short pk / sig). -/
def slhDsaVerifyImpl (p : SlhDsaParams) (msg sig pk : ByteArray) : Bool :=
  let n        := p.n
  let mdLen    := (p.k * p.a + 7) / 8
  let treeLen  := (p.h - p.hp + 7) / 8
  let leafLen  := (p.hp + 7) / 8
  let digLen   := mdLen + treeLen + leafLen
  -- Step 1: parse pubkey.
  let pkSeed   := slice pk 0 n
  let pkRoot   := slice pk n n
  -- Step 2: parse signature.
  let R          := slice sig 0 n
  let forsLen    := p.k * (1 + p.a) * n
  let xmssLen    := (p.len + p.hp) * n
  let forsSig    := slice sig n forsLen
  let htSig      := slice sig (n + forsLen) (p.d * xmssLen)
  -- Step 3: compute Hmsg digest.
  let digest     := hMsg R pkSeed pkRoot msg digLen
  let md         := slice digest 0 mdLen
  let treeBytes  := slice digest mdLen treeLen
  let leafBytes  := slice digest (mdLen + treeLen) leafLen
  let treeIdx0   := beToNat treeBytes % Nat.pow 2 (p.h - p.hp)
  let leafIdx0   := beToNat leafBytes % Nat.pow 2 p.hp
  -- Step 4: recover FORS public key.
  let forsPk     := forsPkFromSig pkSeed forsSig md n treeIdx0 leafIdx0 p.a p.k
  -- Step 5: climb the hypertree d layers.
  let finalRoot  :=
    htClimb pkSeed n p.hp p.len p.len1 0 p.d treeIdx0 leafIdx0 forsPk htSig
  -- Step 6: compare to pkRoot.
  decide (finalRoot.toList = pkRoot.toList)

end SlhDsa

/-- FIPS 205 SLH-DSA-SHA2-128s verifier (n=16, h=63, d=7, a=12, k=14). -/
def verifySLHDSA_SHA2_128s (msg sig pk : ByteArray) : Bool :=
  SlhDsa.slhDsaVerifyImpl SlhDsa.params128s msg sig pk

/-- FIPS 205 SLH-DSA-SHA2-128f verifier (n=16, h=66, d=22, a=6, k=33). -/
def verifySLHDSA_SHA2_128f (msg sig pk : ByteArray) : Bool :=
  SlhDsa.slhDsaVerifyImpl SlhDsa.params128f msg sig pk

/-- FIPS 205 SLH-DSA-SHA2-192s verifier (n=24, h=63, d=7, a=14, k=17). -/
def verifySLHDSA_SHA2_192s (msg sig pk : ByteArray) : Bool :=
  SlhDsa.slhDsaVerifyImpl SlhDsa.params192s msg sig pk

/-- FIPS 205 SLH-DSA-SHA2-192f verifier (n=24, h=66, d=22, a=8, k=33). -/
def verifySLHDSA_SHA2_192f (msg sig pk : ByteArray) : Bool :=
  SlhDsa.slhDsaVerifyImpl SlhDsa.params192f msg sig pk

/-- FIPS 205 SLH-DSA-SHA2-256s verifier (n=32, h=64, d=8, a=14, k=22). -/
def verifySLHDSA_SHA2_256s (msg sig pk : ByteArray) : Bool :=
  SlhDsa.slhDsaVerifyImpl SlhDsa.params256s msg sig pk

/-- FIPS 205 SLH-DSA-SHA2-256f verifier (n=32, h=68, d=17, a=8, k=35). -/
def verifySLHDSA_SHA2_256f (msg sig pk : ByteArray) : Bool :=
  SlhDsa.slhDsaVerifyImpl SlhDsa.params256f msg sig pk

-- Bitcoin BIP-143 preimage projections (operate on opaque SigHashPreimage bytes).
--
-- These were `axiom`s in earlier tiers. Tier 4.3.b (2026-05-10) converts each
-- to a concrete `def` over the BIP-143 byte layout. The layout (per
-- `Stack/TxContext.lean#buildPreimage`) is:
--
--   [ 0..  3] version       (4 bytes LE Int)
--   [ 4.. 35] hashPrevouts  (32 bytes)
--   [36.. 67] hashSequence  (32 bytes)
--   [68..103] outpoint      (36 bytes)
--   [104..  ] VarInt(scriptCodeLen) and scriptCode (variable)
--   [..]      amount        (8 bytes LE Int)
--   [..]      sequence      (4 bytes LE Int)
--   [..]      hashOutputs   (32 bytes)
--   [..]      locktime      (4 bytes LE Int)
--   [..]      sigHashType   (4 bytes LE Int)
--
-- The trailing five fields together occupy exactly
-- 8 + 4 + 32 + 4 + 4 = 52 bytes, so they can be addressed by
-- `preimage.size - N` offsets without needing to decode the scriptCode
-- VarInt prefix.
--
-- `extractInputIndex` is not actually present in the BIP-143 preimage bytes
-- (the input index is the consumer of `OP_CHECKSIG`, not in the digest).
-- It is kept as a `def` returning 0 for backward compatibility with the
-- builtin table in `ANF/Typed.lean#builtinSig`.

/-- Read the byte at offset `i` of `preimage`, returning 0 if out of bounds.
Used by `decodeLE32` / `decodeLE64` to avoid carrying bounds proofs through
the let-bindings. -/
def readByte (preimage : ByteArray) (i : Nat) : Nat :=
  if h : i < preimage.size then (preimage.get i h).toNat else 0

/-- Decode 4 bytes at offset `i` of `preimage` as a little-endian `Int`.
Out-of-range bytes are treated as 0 (per `readByte`). -/
def decodeLE32 (preimage : ByteArray) (i : Nat) : Int :=
  let b0 := readByte preimage i
  let b1 := readByte preimage (i + 1)
  let b2 := readByte preimage (i + 2)
  let b3 := readByte preimage (i + 3)
  (Int.ofNat (b0 + (b1 <<< 8) + (b2 <<< 16) + (b3 <<< 24)))

/-- Decode 8 bytes at offset `i` of `preimage` as a little-endian `Int`.
Out-of-range bytes are treated as 0 (per `readByte`). -/
def decodeLE64 (preimage : ByteArray) (i : Nat) : Int :=
  let b0 := readByte preimage i
  let b1 := readByte preimage (i + 1)
  let b2 := readByte preimage (i + 2)
  let b3 := readByte preimage (i + 3)
  let b4 := readByte preimage (i + 4)
  let b5 := readByte preimage (i + 5)
  let b6 := readByte preimage (i + 6)
  let b7 := readByte preimage (i + 7)
  (Int.ofNat (b0 + (b1 <<< 8) + (b2 <<< 16) + (b3 <<< 24)
            + (b4 <<< 32) + (b5 <<< 40) + (b6 <<< 48) + (b7 <<< 56)))

def decodeLE16Nat (preimage : ByteArray) (i : Nat) : Nat :=
  let b0 := readByte preimage i
  let b1 := readByte preimage (i + 1)
  b0 + (b1 <<< 8)

def decodeLE32Nat (preimage : ByteArray) (i : Nat) : Nat :=
  let b0 := readByte preimage i
  let b1 := readByte preimage (i + 1)
  let b2 := readByte preimage (i + 2)
  let b3 := readByte preimage (i + 3)
  b0 + (b1 <<< 8) + (b2 <<< 16) + (b3 <<< 24)

def decodeLE64Nat (preimage : ByteArray) (i : Nat) : Nat :=
  let b0 := readByte preimage i
  let b1 := readByte preimage (i + 1)
  let b2 := readByte preimage (i + 2)
  let b3 := readByte preimage (i + 3)
  let b4 := readByte preimage (i + 4)
  let b5 := readByte preimage (i + 5)
  let b6 := readByte preimage (i + 6)
  let b7 := readByte preimage (i + 7)
  b0 + (b1 <<< 8) + (b2 <<< 16) + (b3 <<< 24)
    + (b4 <<< 32) + (b5 <<< 40) + (b6 <<< 48) + (b7 <<< 56)

/--
Decode the Bitcoin CompactSize prefix at `offset`, returning
`(payloadStart, payloadLength)`. Out-of-range bytes decode as zero via
`readByte`, matching the total extractor convention above.
-/
def decodeCompactSizeAt (preimage : ByteArray) (offset : Nat) : Nat × Nat :=
  let tag := readByte preimage offset
  if tag < 0xfd then
    (offset + 1, tag)
  else if tag = 0xfd then
    (offset + 3, decodeLE16Nat preimage (offset + 1))
  else if tag = 0xfe then
    (offset + 5, decodeLE32Nat preimage (offset + 1))
  else
    (offset + 9, decodeLE64Nat preimage (offset + 1))

def extractVersion      (preimage : ByteArray) : Int       := decodeLE32 preimage 0
def extractHashPrevouts (preimage : ByteArray) : ByteArray := preimage.extract 4 36
def extractHashSequence (preimage : ByteArray) : ByteArray := preimage.extract 36 68
def extractOutpoint     (preimage : ByteArray) : ByteArray := preimage.extract 68 104
def extractInputIndex   (_preimage : ByteArray) : Int      := 0
def extractScriptCode   (preimage : ByteArray) : ByteArray :=
  let (start, len) := decodeCompactSizeAt preimage 104
  preimage.extract start (start + len)
def extractAmount       (preimage : ByteArray) : Int       := decodeLE64 preimage (preimage.size - 52)
def extractSequence     (preimage : ByteArray) : Int       := decodeLE32 preimage (preimage.size - 44)
def extractOutputHash   (preimage : ByteArray) : ByteArray := preimage.extract (preimage.size - 40) (preimage.size - 8)
def extractLocktime     (preimage : ByteArray) : Int       := decodeLE32 preimage (preimage.size - 8)
def extractSigHashType  (preimage : ByteArray) : Int       := decodeLE32 preimage (preimage.size - 4)

-- Signature verifiers are supplied by the execution environment. The
-- `checkMultiSigStack` field preserves the Stack VM's current single-byte
-- abstraction for `OP_CHECKMULTISIG` until full stack parsing is modelled.
structure AuthBackend where
  checkSig : ByteArray → ByteArray → Bool
  checkMultiSig : List ByteArray → List ByteArray → Bool
  checkMultiSigStack : ByteArray → Bool

private def missingAuthBackend (name : String) : Bool :=
  panic! s!"external {name} auth backend required for Lean execution"

private def executableAuthBackend : AuthBackend where
  checkSig := fun _ _ => missingAuthBackend "checkSig"
  checkMultiSig := fun _ _ => missingAuthBackend "checkMultiSig"
  checkMultiSigStack := fun _ => missingAuthBackend "checkMultiSigStack"

@[implemented_by executableAuthBackend]
axiom authBackend : AuthBackend

def checkSig (sig pubkey : ByteArray) : Bool :=
  authBackend.checkSig sig pubkey

def checkMultiSig (sigs pubkeys : List ByteArray) : Bool :=
  authBackend.checkMultiSig sigs pubkeys

def checkMultiSigStack (payload : ByteArray) : Bool :=
  authBackend.checkMultiSigStack payload
-- Preimage validation is supplied by the execution environment. The
-- concrete BIP-143 byte layout is modelled by `Stack.TxContext`; this
-- backend decides whether a candidate payload is valid for the implicit
-- transaction context used by the script under evaluation.
structure PreimageBackend where
  checkPreimage : ByteArray → Bool

private def missingPreimageBackend (name : String) : Bool :=
  panic! s!"external {name} preimage backend required for Lean execution"

private def executablePreimageBackend : PreimageBackend where
  checkPreimage := fun _ => missingPreimageBackend "checkPreimage"

@[implemented_by executablePreimageBackend]
axiom preimageBackend : PreimageBackend

def checkPreimage (preimage : ByteArray) : Bool :=
  preimageBackend.checkPreimage preimage

-- Output construction.
--
-- These are not crypto primitives but compound, deterministic byte-layout
-- helpers used by the stateful-continuation lowering. The TypeScript
-- reference is `packages/runar-compiler/src/passes/05-stack-lower.ts`:
-- `lowerBuildChangeOutput` (≈ line 2426) and `lowerComputeStateOutput`
-- (≈ line 2336). Earlier tiers axiomatized both; Tier B11 (2026-05-16)
-- converts them to concrete `def`s over the same byte layout the stack
-- lowering emits at runtime.

/--
Local VarInt (Bitcoin CompactSize) encoder, scoped to the output-builders.

* `n < 0xfd`              → 1 byte: `n`
* `n ≤ 0xffff`            → 3 bytes: `0xfd` ++ LE(n, 2)
* `n ≤ 0xffffffff`        → 5 bytes: `0xfe` ++ LE(n, 4)
* otherwise               → 9 bytes: `0xff` ++ LE(n, 8)

Mirrors `Stack.encodeVarInt` in `Stack/TxContext.lean`; duplicated here to
avoid an import cycle (the Stack module imports this `Eval` module).
-/
def encodeVarIntLocal (n : Nat) : ByteArray :=
  if n < 0xfd then
    ByteArray.mk #[n.toUInt8]
  else if n ≤ 0xffff then
    ByteArray.mk #[
      0xfd,
      (n &&& 0xff).toUInt8,
      ((n >>> 8) &&& 0xff).toUInt8
    ]
  else if n ≤ 0xffffffff then
    ByteArray.mk #[
      0xfe,
      (n &&& 0xff).toUInt8,
      ((n >>> 8) &&& 0xff).toUInt8,
      ((n >>> 16) &&& 0xff).toUInt8,
      ((n >>> 24) &&& 0xff).toUInt8
    ]
  else
    ByteArray.mk #[
      0xff,
      (n &&& 0xff).toUInt8,
      ((n >>> 8) &&& 0xff).toUInt8,
      ((n >>> 16) &&& 0xff).toUInt8,
      ((n >>> 24) &&& 0xff).toUInt8,
      ((n >>> 32) &&& 0xff).toUInt8,
      ((n >>> 40) &&& 0xff).toUInt8,
      ((n >>> 48) &&& 0xff).toUInt8,
      ((n >>> 56) &&& 0xff).toUInt8
    ]

/--
Encode a script-number into exactly `width` bytes (matches `OP_NUM2BIN`).

Returns `ByteArray.empty` on overflow — this matches the spec convention
elsewhere in `Eval` (out-of-range bytes treated as 0 / empty). The stack
lowering of `buildChangeOutput` / `computeStateOutput` pushes `width = 8`
right before `OP_NUM2BIN`, so the satoshi amounts are always 8 bytes for
in-range values and the BIP-143 layout is preserved.
-/
def numToBinFixed (n : Int) (width : Nat) : ByteArray :=
  (RunarVerification.Stack.num2binEncode? n width).getD ByteArray.empty

/--
`buildChangeOutput pkh amount` — P2PKH change output bytes.

Mirrors `lowerBuildChangeOutput` in `05-stack-lower.ts`. The on-chain
layout is:

```
  amount(8LE script-number)  ++  0x19 76 a9 14  ++  pkh(20)  ++  0x88 ac
```

Total: `8 + 1 + 3 + 20 + 2 = 34` bytes when `pkh.size = 20`. The leading
`0x19` is the varint length of the P2PKH locking script (25 bytes).
This `def` does not enforce `pkh.size = 20`; it concatenates whatever
`pkh` bytes the caller supplies, exactly matching what `OP_CAT` does at
runtime.
-/
def buildChangeOutput (pkh : ByteArray) (amount : Int) : ByteArray :=
  numToBinFixed amount 8
    ++ ByteArray.mk #[0x19, 0x76, 0xa9, 0x14]
    ++ pkh
    ++ ByteArray.mk #[0x88, 0xac]

/--
`computeStateOutput preimage stateBytes newAmount` — single-output
stateful-continuation locking-script bytes (without the trailing
`OP_HASH256`).

Mirrors `lowerComputeStateOutput` in `05-stack-lower.ts`. The on-chain
layout is:

```
  amount(8LE script-number)
    ++ VarInt(codePart.size + 1 + stateBytes.size)
    ++ codePart
    ++ 0x6a             -- OP_RETURN
    ++ stateBytes
```

Where `amount` is the second-output continuation amount (i.e.
`newAmount`, **not** the spent input's `extractAmount preimage`), and
`codePart` is the post-`OP_CODESEPARATOR` script suffix — supplied
implicitly by the SDK at runtime via the `_codePart` stack-implicit
parameter the stack lowering picks from the alt-stack.

The ANF interpreter does not currently carry `codePart`: the
`get_state_script` ANF intrinsic returns the empty byte payload (see
`evalValue` for `.getStateScript`). Consequently, when the executable
interpreter evaluates a `computeStateOutput` call, the bytes returned
are precisely the stripped layout

```
  amount(8LE)  ++  VarInt(1 + stateBytes.size)  ++  0x6a  ++  stateBytes
```

— i.e. the spec evaluated at `codePart := ByteArray.empty`. This is the
honest semantics for the Lean ANF level; carrying `codePart` is a
deferred Stack-VM follow-up tied to the artifact's compiled `codePart`
field.

The first argument (`preimage`) is unused in the bytes the function
returns: the stack lowering only consults `preimage` for the legacy
"extract amount from preimage" path; the modern path (and the one this
spec captures) uses the explicit `newAmount` argument instead. The
parameter is retained on the signature so the call-site arity in
`callBuiltin?` matches the ANF emit order in `04-anf-lower.ts:238`.
-/
def computeStateOutput
    (_preimage : ByteArray) (stateBytes : ByteArray) (newAmount : Int) : ByteArray :=
  let payload :=
    ByteArray.empty           -- codePart placeholder; see docstring
      ++ ByteArray.mk #[0x6a] -- OP_RETURN
      ++ stateBytes
  numToBinFixed newAmount 8
    ++ encodeVarIntLocal payload.size
    ++ payload

end Crypto

/-! ## Built-in dispatch (concrete cases only)

A small table of pure built-ins handled directly in Lean. Anything not
in this table falls through to the `Crypto` axioms via
`callBuiltin?`, returning `none` for unsupported / framework-internal
calls (which a future iteration of `Eval` will flesh out).
-/

private def evalCat? : List Value → Option Value
  | [a, b] =>
      match a.asBytes?, b.asBytes? with
      | some ba, some bb => some (.vBytes (ba ++ bb))
      | _, _ => none
  | _ => none

private def evalLen? : List Value → Option Value
  | [v] => v.asBytes?.map (fun b => .vBigint b.size)
  | _ => none

private def nonNegativeNatArg (func argName : String) (i : Int) : EvalResult Nat :=
  if i < 0 then
    .error (.typeError s!"{func} expects non-negative {argName}")
  else
    return i.toNat

private def evalNum2bin? (func : String) : List Value → EvalResult (Option Value)
  | [.vBigint n, .vBigint target] => do
      let size ← nonNegativeNatArg func "byte length" target
      match RunarVerification.Stack.num2binEncode? n size with
      | some out => return some (.vBytes out)
      | none => .error (.typeError s!"{func} value does not fit byte length")
  | _ => return none

private def evalBin2num? : List Value → EvalResult (Option Value)
  | [v] =>
      match v.asBytes? with
      | some bytes => return some (.vBigint (RunarVerification.Stack.decodeMinimalLE bytes))
      | none => return none
  | _ => return none

private def sliceBytes (bs : ByteArray) (start len : Nat) : ByteArray :=
  bs.extract start (start + len)

private def evalSubstr? : List Value → EvalResult (Option Value)
  | [v, .vBigint start, .vBigint len] => do
      match v.asBytes? with
      | some bs =>
          let start' ← nonNegativeNatArg "substr" "start" start
          let len' ← nonNegativeNatArg "substr" "length" len
          return some (.vBytes (sliceBytes bs start' len'))
      | none => return none
  | _ => return none

private def evalLeft? : List Value → EvalResult (Option Value)
  | [v, .vBigint len] => do
      match v.asBytes? with
      | some bs =>
          let len' ← nonNegativeNatArg "left" "length" len
          return some (.vBytes (sliceBytes bs 0 len'))
      | none => return none
  | _ => return none

private def evalRight? : List Value → EvalResult (Option Value)
  | [v, .vBigint len] => do
      match v.asBytes? with
      | some bs =>
          let len' ← nonNegativeNatArg "right" "length" len
          let start := bs.size - len'
          return some (.vBytes (bs.extract start bs.size))
      | none => return none
  | _ => return none

private def evalSplit? : List Value → EvalResult (Option Value)
  | [v, .vBigint index] => do
      match v.asBytes? with
      | some bs =>
          let index' ← nonNegativeNatArg "split" "index" index
          -- The compiler names the right/top OP_SPLIT result as the
          -- builtin call value; the left part remains unnamed on the stack.
          return some (.vBytes (bs.extract index' bs.size))
      | none => return none
  | _ => return none

private def evalReverseBytes? : List Value → EvalResult (Option Value)
  | [v] =>
      match v.asBytes? with
      | some bs => return some (.vBytes (ByteArray.mk (bs.toList.reverse.toArray)))
      | none => return none
  | _ => return none

private def evalToByteString? : List Value → EvalResult (Option Value)
  | [v] =>
      match v.asBytes? with
      | some bs => return some (.vBytes bs)
      | none => return none
  | _ => return none

private def evalPack? : List Value → EvalResult (Option Value)
  | [.vBigint i] => return some (.vBytes (RunarVerification.Stack.encodeMinimalLE i))
  | _ => return none

/-! ### Bounded pure-math helpers

Concrete `def`s for the math builtins listed in the A4 corpus (Tier B11
follow-up). Each helper mirrors the TypeScript reference in
`packages/runar-lang/src/runtime/builtins.ts` and is wired into
`callBuiltin?` below. No new axioms — looping helpers (`pow`, `sqrtInt`,
`gcdInt`, `log2Int`) terminate via either structural `Nat` recursion or
`Nat.log2`-bounded fuel.
-/

/-- Non-negative-integer exponentiation. Structurally recursive on the
exponent. The TS reference (`builtins.ts#pow`) throws on negative
exponents; the dispatch arm rejects them with `.typeError`. -/
private def powNat (base : Int) : Nat → Int
  | 0     => 1
  | n + 1 => base * powNat base n

/-- Newton-step iteration for `Nat.sqrt`. `fuel` is structurally
decreasing; in practice `Nat.log2 n + 2` iterations suffice but we
allocate a generous `+ 32` margin in the wrapper. -/
private def sqrtNewton : Nat → Nat → Nat → Nat
  | 0,        _, x => x
  | fuel + 1, n, x =>
      if x = 0 then 0
      else
        let y := (x + n / x) / 2
        if y < x then sqrtNewton fuel n y else x

/-- Integer square root. Matches the TS reference's seeded Newton's
method (`builtins.ts#sqrt`): start from `x = n`, iterate while the next
candidate decreases. Returns `0` on `n = 0`. The dispatch arm in
`callBuiltin?` rejects negative inputs with `.typeError`. -/
private def sqrtNat (n : Nat) : Nat :=
  if n = 0 then 0 else sqrtNewton (Nat.log2 n + 32) n n

/-- `gcd` on `Int` via `Nat.gcd` on the absolute values. The TS
reference (`builtins.ts#gcd`) takes `|a|` and `|b|` before iterating. -/
private def gcdInt (a b : Int) : Int :=
  Int.ofNat (Nat.gcd a.natAbs b.natAbs)

/-- Floor-`log2` on a positive integer, lifted to `Int`. Matches the TS
reference (`builtins.ts#log2`) which right-shifts until the value
becomes `≤ 1`. The dispatch arm rejects non-positive inputs with
`.typeError`. -/
private def log2Int (i : Int) : Int :=
  Int.ofNat (Nat.log2 i.toNat)

/--
Best-effort dispatch for the documented "concrete" built-ins. Returns
`none` for any built-in that is intentionally axiomatized at this stage;
the caller treats `none` as `EvalError.unsupported` for now.
-/
def callBuiltin? (func : String) (args : List Value) : EvalResult (Option Value) :=
  match func with
  | "cat"  => return evalCat? args
  | "len"  => return evalLen? args
  | "substr" => evalSubstr? args
  | "num2bin" => evalNum2bin? "num2bin" args
  | "bin2num" => evalBin2num? args
  | "int2str" => evalNum2bin? "int2str" args
  | "unpack" => evalBin2num? args
  | "pack" => evalPack? args
  | "split" => evalSplit? args
  | "reverseBytes" => evalReverseBytes? args
  | "left" => evalLeft? args
  | "right" => evalRight? args
  | "toByteString" => evalToByteString? args
  | "abs" =>
      match args with
      | [.vBigint i] => return some (.vBigint i.natAbs)
      | _ => return none
  | "min" =>
      match args with
      | [.vBigint a, .vBigint b] => return some (.vBigint (min a b))
      | _ => return none
  | "max" =>
      match args with
      | [.vBigint a, .vBigint b] => return some (.vBigint (max a b))
      | _ => return none
  | "within" =>
      match args with
      | [.vBigint x, .vBigint lo, .vBigint hi] =>
          return some (.vBool (decide (lo ≤ x ∧ x < hi)))
      | _ => return none
  | "safediv" =>
      match args with
      | [.vBigint a, .vBigint b] =>
          if b == 0 then .error .divByZero else return some (.vBigint (a / b))
      | _ => return none
  | "safemod" =>
      match args with
      | [.vBigint a, .vBigint b] =>
          if b == 0 then .error .divByZero else return some (.vBigint (a % b))
      | _ => return none
  | "divmod" =>
      -- TS reference: `divmod(a, b)` returns the quotient `a / b` (the
      -- compiler synthesises an OP_DIV after OP_2DUP / OP_MOD / OP_DROP
      -- — only the quotient is named). Zero divisor is rejected.
      match args with
      | [.vBigint a, .vBigint b] =>
          if b == 0 then .error .divByZero else return some (.vBigint (a / b))
      | _ => return none
  | "clamp" =>
      match args with
      | [.vBigint x, .vBigint lo, .vBigint hi] =>
          return some (.vBigint (min (max x lo) hi))
      | _ => return none
  | "sign" =>
      match args with
      | [.vBigint i] =>
          let s : Int := if i = 0 then 0 else if i > 0 then 1 else -1
          return some (.vBigint s)
      | _ => return none
  | "mulDiv" =>
      match args with
      | [.vBigint a, .vBigint b, .vBigint c] =>
          if c == 0 then .error .divByZero
          else return some (.vBigint ((a * b) / c))
      | _ => return none
  | "percentOf" =>
      match args with
      | [.vBigint amount, .vBigint bps] =>
          return some (.vBigint ((amount * bps) / 10000))
      | _ => return none
  | "pow" =>
      match args with
      | [.vBigint base, .vBigint exp] =>
          if exp < 0 then
            .error (.typeError "pow expects non-negative exponent")
          else
            return some (.vBigint (powNat base exp.toNat))
      | _ => return none
  | "sqrt" =>
      match args with
      | [.vBigint n] =>
          if n < 0 then
            .error (.typeError "sqrt expects non-negative input")
          else
            return some (.vBigint (Int.ofNat (sqrtNat n.toNat)))
      | _ => return none
  | "gcd" =>
      match args with
      | [.vBigint a, .vBigint b] => return some (.vBigint (gcdInt a b))
      | _ => return none
  | "log2" =>
      match args with
      | [.vBigint n] =>
          if n ≤ 0 then
            .error (.typeError "log2 expects positive input")
          else
            return some (.vBigint (log2Int n))
      | _ => return none
  | "super" =>
      -- super(...) is a constructor-delegation marker with no
      -- runtime effect in eval; we return the @this marker.
      -- See `packages/runar-lang/src/index.ts` (SmartContract /
      -- StatefulSmartContract constructors) — `super(...)` in the
      -- source is a positional property-assignment delegation that
      -- the parser already lowers into PropertyNode initializers,
      -- so the residual ANF call has no remaining runtime effect.
      return some .vThis
  | "extractOutputHash" =>
      -- Compound BIP-143 projection: bytes [size-40, size-8) of the
      -- preimage (= the `hashOutputs` field). Already a concrete `def`
      -- in `Crypto.extractOutputHash` (line ~425); we expose it through
      -- the builtin dispatch so ANF `call extractOutputHash(preimage)`
      -- nodes resolve at evaluator time instead of falling through to
      -- `.unsupported`.
      match args with
      | [v] =>
          match v.asBytes? with
          | some bytes => return some (.vBytes (Crypto.extractOutputHash bytes))
          | none => return none
      | _ => return none
  | "buildChangeOutput" =>
      -- Compound P2PKH-change-output builder. Concrete spec lives in
      -- `Crypto.buildChangeOutput`.
      match args with
      | [pkhV, amountV] =>
          match pkhV.asBytes?, amountV.asInt? with
          | some pkh, some amount =>
              return some (.vBytes (Crypto.buildChangeOutput pkh amount))
          | _, _ => return none
      | _ => return none
  | "computeStateOutput" =>
      -- Compound stateful-continuation output builder. Concrete spec
      -- lives in `Crypto.computeStateOutput`.
      match args with
      | [preV, stateV, amountV] =>
          match preV.asBytes?, stateV.asBytes?, amountV.asInt? with
          | some pre, some state, some amount =>
              return some (.vBytes (Crypto.computeStateOutput pre state amount))
          | _, _, _ => return none
      | _ => return none
  | "bool" =>
      match args with
      | [.vBigint i] => return some (.vBool (decide (i ≠ 0)))
      | [.vBool b]   => return some (.vBool b)
      | _ => return none
  | _ => return none

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
* `bin_op` / `unary_op` — arithmetic / comparison / logical / shifts;
  `&`, `|`, `^`, `~` are bytewise and match the Stack VM helpers.
* `if` — dispatches on `cond`, recurses into the active branch via
  `evalBindings`. The if-binding's "result" is the value of the last
  binding in the active branch (or `vBool true/false` if empty).
* `loop` — unrolls `count` times, registering `iterVar` as a synthetic
  param visible only inside the body.
* `assert` — fails with `.assertFailed` if the operand is `false`.
* `update_prop` — writes the property slot; returns the assigned value.
* `call` — dispatches the cheap built-ins (`cat`, `len`, `super`,
  `bool`), byte-string slicing, script-number conversions, and numeric
  helpers (`abs`, `min`, `max`, `within`);
  everything else returns `.error .unsupported` for the Phase 3 lead
  to wire to `Crypto`.
* `getStateScript`, `deserializeState` — opaque framework intrinsics
  returning `.vOpaque ByteArray.empty`.
* `addOutput`, `addRawOutput`, `addDataOutput` — append to
  `State.outputs` in canonical declaration order.
* `arrayLiteral` — evaluates each element ref but emits an opaque
  payload (full byte-layout deferred to Phase 3).
* `methodCall` — `.error .unsupported`; per-program method-resolution
  table is Phase 3 work.

Cryptographic primitives still return `.error .unsupported` and are
listed as axioms in `Eval.Crypto`.
-/
def evalValue (s : State) : ANFValue → EvalResult (Value × State)
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
      match ← callBuiltin? func argVs with
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
      -- Termination: `count` is a `Nat` — `runLoop` recurses on
      -- `count - 1`, so the outer fuel-driven step in the unified
      -- mutual measure decreases lexicographically before re-entering
      -- `evalBindings`/`evalValue` on `body`.
      let s' ← runLoop count body iterVar s
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
      -- Framework intrinsic — the standalone ANF evaluator does not
      -- carry the compiled artifact's `codePart`, so it returns an
      -- opaque payload.
      .ok (.vOpaque ByteArray.empty, s)
  | .checkPreimage preimage => do
      let pv ← lookupRef s preimage
      match pv.asBytes? with
      | some bytes => .ok (.vBool (Crypto.checkPreimage bytes), s)
      | none => .error (.typeError "checkPreimage expects bytes")
  | .deserializeState _preimage =>
      -- Framework intrinsic: in production, parses the codePart bytes
      -- of the preimage into the contract's mutable property slots.
      -- The executable ANF evaluator keeps the parsed state payload
      -- opaque; stack-level state extraction is modelled in
      -- `Stack.Lower`.
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
  | .rawScript bytes _inArity _outArity =>
      -- A `raw_script` node embeds a verbatim opcode-byte span. The
      -- stack-lowering pass emits the bytes through a single
      -- `raw_bytes` StackOp without inspecting them; for the ANF
      -- evaluator we mirror that by binding the binding-name to the
      -- raw-byte payload itself. Stack-effect arity (`inArity` /
      -- `outArity`) is the operational lowerer's concern; the ANF
      -- interpreter exposes a single result value per binding by
      -- convention, matching the named slot the TS lowering pushes
      -- on the stackmap for the single-out case
      -- (`05-stack-lower.ts:1077-1080`).
      .ok (.vBytes bytes, s)

/--
Evaluate a sequence of bindings, threading state through. Each binding
adds its computed value to `state.bindings` so subsequent refs resolve.
-/
def evalBindings (s : State) : List ANFBinding → EvalResult State
  | [] => .ok s
  | .mk name v _ :: rest => do
      let (val, s') ← evalValue s v
      evalBindings (s'.addBinding name val) rest

/--
Run `count` iterations of a loop body, registering `iterVar` as a
synthetic parameter equal to the current iteration index (0-based).
After each iteration the synthetic param is stripped so subsequent
iterations bind a fresh value.

`count` is the remaining iteration budget — recursion decreases it by
one each step, giving a structural termination measure on `Nat`. The
outer `evalValue.loop` arm passes the original count from the ANFValue
so the iteration count exactly matches the source-level `loop` count.
-/
def runLoop (count : Nat) (body : List ANFBinding)
    (iterVar : String) (s : State) : EvalResult State :=
  match count with
  | 0 => .ok s
  | n + 1 =>
      let withIter : State :=
        { s with params := (iterVar, .vBigint n) :: s.params }
      match evalBindings withIter body with
      | .error e => .error e
      | .ok s' =>
          let stripped : State :=
            { s' with params := s'.params.filter (·.fst != iterVar) }
          runLoop n body iterVar stripped

end

/-! ### Concrete ANF byte / number samples

Executable samples pin the ANF evaluator to the same bytewise and
script-number helpers used by the Stack VM.
-/

theorem evalBinOp_XOR_bytes_sample :
    (match evalBinOp "^"
        (.vBytes (ByteArray.mk #[0x0f]))
        (.vBytes (ByteArray.mk #[0xf0]))
        none with
     | .ok (.vBytes out) => out.toList == [0xff]
     | _ => false) = true := by
  native_decide

theorem evalBinOp_AND_length_mismatch_errors :
    (match evalBinOp "&"
        (.vBytes (ByteArray.mk #[0x0f]))
        (.vBytes (ByteArray.mk #[0xf0, 0x00]))
        none with
     | .error (.typeError _) => true
     | _ => false) = true := by
  native_decide

theorem callBuiltin_num2bin_sample :
    (match callBuiltin? "num2bin" [.vBigint (-128), .vBigint 4] with
     | .ok (some (.vBytes out)) => out.toList == [0x80, 0x00, 0x00, 0x80]
     | _ => false) = true := by
  native_decide

theorem callBuiltin_bin2num_sample :
    (match callBuiltin? "bin2num" [.vBytes (ByteArray.mk #[0x80, 0x80])] with
     | .ok (some (.vBigint n)) => n == -128
     | _ => false) = true := by
  native_decide

theorem callBuiltin_substr_sample :
    (match callBuiltin? "substr"
        [.vBytes (ByteArray.mk #[0x01, 0x02, 0x03, 0x04]), .vBigint 1, .vBigint 2] with
     | .ok (some (.vBytes out)) => out.toList == [0x02, 0x03]
     | _ => false) = true := by
  native_decide

theorem callBuiltin_split_returns_suffix_sample :
    (match callBuiltin? "split"
        [.vBytes (ByteArray.mk #[0x01, 0x02, 0x03, 0x04]), .vBigint 2] with
     | .ok (some (.vBytes out)) => out.toList == [0x03, 0x04]
     | _ => false) = true := by
  native_decide

theorem callBuiltin_abs_sample :
    (match callBuiltin? "abs" [.vBigint (-9)] with
     | .ok (some (.vBigint n)) => n == 9
     | _ => false) = true := by
  native_decide

theorem callBuiltin_min_sample :
    (match callBuiltin? "min" [.vBigint 7, .vBigint (-3)] with
     | .ok (some (.vBigint n)) => n == -3
     | _ => false) = true := by
  native_decide

theorem callBuiltin_max_sample :
    (match callBuiltin? "max" [.vBigint 7, .vBigint (-3)] with
     | .ok (some (.vBigint n)) => n == 7
     | _ => false) = true := by
  native_decide

theorem callBuiltin_within_true_sample :
    (match callBuiltin? "within" [.vBigint 7, .vBigint 3, .vBigint 9] with
     | .ok (some (.vBool b)) => b == true
     | _ => false) = true := by
  native_decide

theorem callBuiltin_within_false_at_hi_sample :
    (match callBuiltin? "within" [.vBigint 9, .vBigint 3, .vBigint 9] with
     | .ok (some (.vBool b)) => b == false
     | _ => false) = true := by
  native_decide

theorem evalValue_call_abs_sample :
    (match evalValue { (default : State) with bindings := [("x", .vBigint (-9))] }
        (.call "abs" ["x"]) with
     | .ok (.vBigint n, _) => n == 9
     | _ => false) = true := by
  native_decide

theorem evalValue_call_min_sample :
    (match evalValue
        { (default : State) with bindings := [("r", .vBigint (-3)), ("l", .vBigint 7)] }
        (.call "min" ["l", "r"]) with
     | .ok (.vBigint n, _) => n == -3
     | _ => false) = true := by
  native_decide

theorem evalValue_call_within_sample :
    (match evalValue
        { (default : State) with
          bindings := [("hi", .vBigint 9), ("lo", .vBigint 3), ("x", .vBigint 7)] }
        (.call "within" ["x", "lo", "hi"]) with
     | .ok (.vBool b, _) => b == true
     | _ => false) = true := by
  native_decide

/-! ### Compound builtin samples (B11)

Executable samples pin the concrete `buildChangeOutput` /
`computeStateOutput` / `extractOutputHash` semantics against the
byte-exact layouts the TypeScript stack lowering emits.
-/

/-- `buildChangeOutput pkh amount` produces 34 bytes for a 20-byte
`pkh` and an 8-byte representable `amount` (matches the on-chain
P2PKH change-output layout). -/
theorem buildChangeOutput_p2pkh_layout_sample :
    ((Crypto.buildChangeOutput
        (ByteArray.mk #[
          0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
          0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14])
        5000).toList ==
       [0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x19, 0x76, 0xa9, 0x14,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14,
        0x88, 0xac]) = true := by
  native_decide

/-- `buildChangeOutput` total size is exactly `8 + 4 + pkh.size + 2` —
the 4-byte prefix is `varint(25) ++ DUP ++ HASH160 ++ PUSH20` and the
2-byte suffix is `EQUALVERIFY ++ CHECKSIG`. -/
theorem buildChangeOutput_total_size_sample :
    (Crypto.buildChangeOutput
        (ByteArray.mk (Array.replicate 20 0xab)) 1).size = 34 := by
  native_decide

/-- `computeStateOutput preimage stateBytes newAmount` returns the
amount-prefixed, varint-length-prefixed serialization of
`OP_RETURN ++ stateBytes` (codePart placeholder is empty at the ANF
interpreter level — see the `Crypto.computeStateOutput` docstring). -/
theorem computeStateOutput_empty_codepart_layout_sample :
    ((Crypto.computeStateOutput
        ByteArray.empty
        (ByteArray.mk #[0xaa, 0xbb])
        1).toList ==
      [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x03,
       0x6a,
       0xaa, 0xbb]) = true := by
  native_decide

/-- `extractOutputHash` exposed via `callBuiltin?`: dispatches to the
concrete `Crypto.extractOutputHash` BIP-143 projection. -/
theorem callBuiltin_extractOutputHash_sample :
    (match callBuiltin? "extractOutputHash"
        [.vBytes (ByteArray.mk #[
           -- 156 bytes of fixed-width fields + a 1-byte scriptCode varint
           -- + 1 byte of scriptCode = 158 bytes total; hashOutputs lives
           -- at the size-40..size-8 window.
           0x02, 0x00, 0x00, 0x00,
           0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
           0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
           0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
           0,0,0,0,
           0x01,
           0x51,
           0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00,
           0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
           0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
           0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
           0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
           0x00, 0x00, 0x00, 0x00,
           0x41, 0x00, 0x00, 0x00])] with
     | .ok (some (.vBytes out)) =>
         out.toList == [
           0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
           0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
           0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
           0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef]
     | _ => false) = true := by
  native_decide

/-- `callBuiltin? "super"` returns the `@this` marker. -/
theorem callBuiltin_super_sample :
    (match callBuiltin? "super" [] with
     | .ok (some .vThis) => true
     | _ => false) = true := by
  native_decide

/-- `callBuiltin? "buildChangeOutput"` dispatches to the concrete spec. -/
theorem callBuiltin_buildChangeOutput_sample :
    (match callBuiltin? "buildChangeOutput"
        [.vBytes (ByteArray.mk (Array.replicate 20 0xab)), .vBigint 1] with
     | .ok (some (.vBytes out)) => out.size == 34
     | _ => false) = true := by
  native_decide

/-- `callBuiltin? "computeStateOutput"` dispatches to the concrete spec. -/
theorem callBuiltin_computeStateOutput_sample :
    (match callBuiltin? "computeStateOutput"
        [.vBytes ByteArray.empty,
         .vBytes (ByteArray.mk #[0xaa, 0xbb]),
         .vBigint 1] with
     | .ok (some (.vBytes out)) =>
         out.toList ==
           [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x6a, 0xaa, 0xbb]
     | _ => false) = true := by
  native_decide

/-! ### A4 / B11 math-builtin smoke samples

Pin the concrete arms in `callBuiltin?` for the math/byte builtins
listed in the A4 corpus. Each test runs through `evalValue` to exercise
both the binding lookup and the dispatch.
-/

theorem callBuiltin_safediv_sample :
    (match callBuiltin? "safediv" [.vBigint 10, .vBigint 3] with
     | .ok (some (.vBigint n)) => n == 3
     | _ => false) = true := by
  native_decide

theorem callBuiltin_safediv_div_by_zero :
    (match callBuiltin? "safediv" [.vBigint 10, .vBigint 0] with
     | .error .divByZero => true
     | _ => false) = true := by
  native_decide

theorem callBuiltin_safemod_sample :
    (match callBuiltin? "safemod" [.vBigint 10, .vBigint 3] with
     | .ok (some (.vBigint n)) => n == 1
     | _ => false) = true := by
  native_decide

theorem callBuiltin_divmod_sample :
    (match callBuiltin? "divmod" [.vBigint 17, .vBigint 5] with
     | .ok (some (.vBigint n)) => n == 3
     | _ => false) = true := by
  native_decide

theorem callBuiltin_clamp_below_sample :
    (match callBuiltin? "clamp" [.vBigint (-3), .vBigint 0, .vBigint 10] with
     | .ok (some (.vBigint n)) => n == 0
     | _ => false) = true := by
  native_decide

theorem callBuiltin_clamp_above_sample :
    (match callBuiltin? "clamp" [.vBigint 99, .vBigint 0, .vBigint 10] with
     | .ok (some (.vBigint n)) => n == 10
     | _ => false) = true := by
  native_decide

theorem callBuiltin_clamp_inside_sample :
    (match callBuiltin? "clamp" [.vBigint 5, .vBigint 0, .vBigint 10] with
     | .ok (some (.vBigint n)) => n == 5
     | _ => false) = true := by
  native_decide

theorem callBuiltin_sign_neg_sample :
    (match callBuiltin? "sign" [.vBigint (-9)] with
     | .ok (some (.vBigint n)) => n == -1
     | _ => false) = true := by
  native_decide

theorem callBuiltin_sign_zero_sample :
    (match callBuiltin? "sign" [.vBigint 0] with
     | .ok (some (.vBigint n)) => n == 0
     | _ => false) = true := by
  native_decide

theorem callBuiltin_sign_pos_sample :
    (match callBuiltin? "sign" [.vBigint 42] with
     | .ok (some (.vBigint n)) => n == 1
     | _ => false) = true := by
  native_decide

theorem callBuiltin_mulDiv_sample :
    (match callBuiltin? "mulDiv" [.vBigint 7, .vBigint 11, .vBigint 5] with
     | .ok (some (.vBigint n)) => n == 15
     | _ => false) = true := by
  native_decide

theorem callBuiltin_percentOf_sample :
    -- 5% of 1234 in basis points = (1234 * 500) / 10000 = 61
    (match callBuiltin? "percentOf" [.vBigint 1234, .vBigint 500] with
     | .ok (some (.vBigint n)) => n == 61
     | _ => false) = true := by
  native_decide

theorem callBuiltin_pow_sample :
    (match callBuiltin? "pow" [.vBigint 2, .vBigint 10] with
     | .ok (some (.vBigint n)) => n == 1024
     | _ => false) = true := by
  native_decide

theorem callBuiltin_pow_negative_exp :
    (match callBuiltin? "pow" [.vBigint 2, .vBigint (-1)] with
     | .error (.typeError _) => true
     | _ => false) = true := by
  native_decide

theorem callBuiltin_sqrt_perfect_sample :
    (match callBuiltin? "sqrt" [.vBigint 144] with
     | .ok (some (.vBigint n)) => n == 12
     | _ => false) = true := by
  native_decide

theorem callBuiltin_sqrt_imperfect_sample :
    (match callBuiltin? "sqrt" [.vBigint 145] with
     | .ok (some (.vBigint n)) => n == 12
     | _ => false) = true := by
  native_decide

theorem callBuiltin_sqrt_zero_sample :
    (match callBuiltin? "sqrt" [.vBigint 0] with
     | .ok (some (.vBigint n)) => n == 0
     | _ => false) = true := by
  native_decide

theorem callBuiltin_sqrt_negative_errors :
    (match callBuiltin? "sqrt" [.vBigint (-4)] with
     | .error (.typeError _) => true
     | _ => false) = true := by
  native_decide

theorem callBuiltin_gcd_sample :
    (match callBuiltin? "gcd" [.vBigint 12, .vBigint 18] with
     | .ok (some (.vBigint n)) => n == 6
     | _ => false) = true := by
  native_decide

theorem callBuiltin_gcd_negative_sample :
    (match callBuiltin? "gcd" [.vBigint (-12), .vBigint 18] with
     | .ok (some (.vBigint n)) => n == 6
     | _ => false) = true := by
  native_decide

theorem callBuiltin_log2_sample :
    (match callBuiltin? "log2" [.vBigint 1024] with
     | .ok (some (.vBigint n)) => n == 10
     | _ => false) = true := by
  native_decide

theorem callBuiltin_log2_non_power_of_two :
    -- ⌊log2(1000)⌋ = 9 (since 2^9 = 512, 2^10 = 1024)
    (match callBuiltin? "log2" [.vBigint 1000] with
     | .ok (some (.vBigint n)) => n == 9
     | _ => false) = true := by
  native_decide

theorem callBuiltin_log2_non_positive_errors :
    (match callBuiltin? "log2" [.vBigint 0] with
     | .error (.typeError _) => true
     | _ => false) = true := by
  native_decide

end Eval
end RunarVerification.ANF
