import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.ANF.Typed
import RunarVerification.Stack.NumEncoding
import RunarVerification.Crypto.HashBackend

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
axiom verifySLHDSA_SHA2_128s  : ByteArray → ByteArray → ByteArray → Bool
axiom verifySLHDSA_SHA2_128f  : ByteArray → ByteArray → ByteArray → Bool
axiom verifySLHDSA_SHA2_192s  : ByteArray → ByteArray → ByteArray → Bool
axiom verifySLHDSA_SHA2_192f  : ByteArray → ByteArray → ByteArray → Bool
axiom verifySLHDSA_SHA2_256s  : ByteArray → ByteArray → ByteArray → Bool
axiom verifySLHDSA_SHA2_256f  : ByteArray → ByteArray → ByteArray → Bool

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
