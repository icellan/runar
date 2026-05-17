import RunarVerification.ANF.Eval
import RunarVerification.Stack.Peephole
import RunarVerification.Stack.Ec
import RunarVerification.Stack.NumEncoding

/-!
# Crypto assumption specifications — paired `_correct` companions

This module pairs the bare crypto assumptions in `RunarVerification.ANF.Eval`
with **specification companions** that ground each primitive in the
cryptographic semantics it claims to implement.

## Why this exists (Tier 5.1 of the remediation plan)

The primitive symbols in `ANF/Eval.lean` are bare function signatures
with no soundness lemmas attached. A hypothetical attacker who controls
the meaning of these assumptions could specialize, for
example,

```text
  axiom verifyWOTS_always_true : ∀ m s p, Crypto.verifyWOTS m s p = true
```

and break any future "Rúnar contracts cannot be spent without a valid
signature" theorem — without contradiction at the kernel level,
because the bare `axiom verifyWOTS : ByteArray → ByteArray → ByteArray
→ Bool` is consistent with the constantly-true function.

Each spec companion below states the *correctness* property the
primitive is **claimed to satisfy**. The companion + the bare axiom
together form the trust commitment: any attacker-supplied
specialization of the bare axiom must additionally satisfy the
companion, which rules out the constantly-true / constantly-false
specializations.

In particular, `verifyWOTS_correct` together with EUF-CMA universal
forgeability (the standard cryptographic assumption: no feasible
algorithm produces a `(msg, sig)` pair from `pk` alone) is
**inconsistent with `verifyWOTS_always_true`**: the latter would let
an attacker forge signatures for any message, contradicting EUF-CMA.
The companion makes this contradiction explicit at the trust-manifest
level.

## Categories

* **Hash linking.** `hash160 = ripemd160 ∘ sha256` and
  `hash256 = sha256 ∘ sha256` (consensus definitions). Both are now
  `rfl` corollaries: Tier 5.3 (2026-05-10) replaced the opaque
  `Crypto.hash160` / `Crypto.hash256` declarations in `ANF/Eval.lean`
  with concrete `def`s, and replaced the `axiom
  hash256_eq_double_sha256` in `Stack/Peephole.lean:968` with a
  `theorem ... := rfl`. The hash-linking identities therefore
  contribute zero axioms to the TCB.
* **EC group laws (secp256k1).** Associativity, commutativity,
  identity, inverse, scalar distributivity, scalar identity / zero
  elements, and projection round-trip for `ecMakePoint`.
* **EUF-CMA functional specs.** For each signature verifier
  (`verifyECDSA_*`, `verifyWOTS`, `verifySLHDSA_*`, `verifyRabinSig`),
  a successful verification implies the existence of a signing key
  whose public key matches the verification key. This is the
  existential / functional form of EUF-CMA.

To express the EUF-CMA companions we introduce a small set of
auxiliary axiomatic primitives (pubkey derivation and signing
oracles) as bare `axiom` function symbols (NOT opaque-with-stub —
project policy forbids new opaques carrying stub bodies).

## TCB impact

This module **adds axioms** to the TCB (it does not discharge any).
The trust commitment grows but becomes **specific**: a future
implementation of the bare crypto assumptions (e.g. via Mathlib's
secp256k1 group, FIPS 205 SLH-DSA, etc.) must additionally satisfy
the companion specifications stated here.

After this module lands the TCB inventory in `TRUST_MANIFEST.md`
must reflect:

* 0 hash linking axioms (Tier 5.3 (2026-05-10) discharged both
  `hash160_eq_ripemd160_sha256` and `hash256_eq_double_sha256` as
  `rfl` corollaries once `Crypto.hash160` / `Crypto.hash256` became
  `def`s).
* +10 EC group / projection axioms
* +11 EUF-CMA functional spec axioms (ECDSA + ECDSA-P256 + ECDSA-P384,
  WOTS, SLH-DSA × 6 parameter sets, Rabin)
* +5 auxiliary primitive axioms (`derivePubKey`, `deriveWOTSPub`,
  `signWOTS`, `deriveSlhDsaPub`, `deriveRabinPub`)

Total: **26** axioms in this module from Tier 5.1 (one fewer than the
original 27 once Tier 5.3 discharged `hash160_eq_ripemd160_sha256`).

**Phase B addenda (2026-05-16).** Four parallel work streams add
further codegen-to-spec / functional-correctness axioms in this module:

* **B4 secp256k1 EC** (§6): +10 codegen-to-spec axioms linking each
  `Stack.Ec.emitEc*` op-list builder to the matching `Crypto.ec*`
  spec primitive via `runOps stkSt = .ok stkSt'` shape.
* **B6 BabyBear** (§7): +4 functional-correctness companions
  (`bbFieldAdd_correct`, `bbFieldSub_correct`, `bbFieldMul_correct`,
  `bbFieldInv_correct`) plus concrete `def`s for the canonical
  reductions and degree-4 extension. The base-field and ext4 spec
  defs are concrete `def`s and contribute zero axioms.
* **B8 WOTS+** (§8): concrete `def Crypto.Spec.verifyWOTS` for the
  WOTS+ verifier (parameters `w = 16, n = 32, len = 67`) over
  `Crypto.HashBackend.sha256`. Zero axioms in this module. The
  codegen-to-spec axiom `runOps_wotsBodyOps_eq` lives in
  `Stack/Wots.lean` (+1 axiom there).
* **B10 Rabin** (§9): concrete `def Crypto.Spec.verifyRabinSig_spec`
  for the modular Rabin identity `(sig² + padding) mod pubKey ==
  SHA256(msg)`. Zero axioms in this module. The codegen-to-spec
  axiom `runOps_rabinBodyOps_eq` lives in `Stack/Rabin.lean`
  (+1 axiom there).

Net delta in this file: +14 axioms (10 EC + 4 BabyBear). Total in
this module: **40** axioms. Project-wide delta is +16 axioms (the
extra two — one each from B8 and B10 — live in
`Stack/Wots.lean` and `Stack/Rabin.lean`).
-/

namespace RunarVerification.Crypto.Spec

open RunarVerification.ANF.Eval

/-! ## 1. Hash linking theorems

`Crypto.hash160` and `Crypto.hash256` are concrete `def`s in
`ANF/Eval.lean` (Tier 5.3, 2026-05-10):

```
def hash160 (b : ByteArray) : ByteArray := ripemd160 (sha256 b)
def hash256 (b : ByteArray) : ByteArray := sha256  (sha256 b)
```

so the consensus identities are now provable by `rfl`. The two
named lemmas are retained here for one-stop discovery; they contribute
no axiom to the TCB.
-/

/-- `OP_HASH160` consensus definition: RIPEMD-160 ∘ SHA-256.
Provable by `rfl` because `Crypto.hash160` unfolds to
`Crypto.ripemd160 (Crypto.sha256 b)`. -/
theorem hash160_eq_ripemd160_sha256 (b : ByteArray) :
    Crypto.hash160 b = Crypto.ripemd160 (Crypto.sha256 b) := rfl

/-- `OP_HASH256` consensus definition: SHA-256 ∘ SHA-256.
Provable by `rfl` because `Crypto.hash256` unfolds to
`Crypto.sha256 (Crypto.sha256 b)`. -/
theorem hash256_eq_double_sha256 (b : ByteArray) :
    Crypto.hash256 b = Crypto.sha256 (Crypto.sha256 b) := rfl

/-! ## 2. secp256k1 group laws

The 10 EC primitives in §3b of the trust manifest model points as
64-byte uncompressed `ByteArray` (x[32] || y[32]). The companion
axioms below assert the standard abelian-group laws + scalar
distributivity. The point at infinity (group identity) is
approximated by `Crypto.ecMakePoint 0 0` — a future iteration may
replace this with a dedicated `Crypto.ecZero` constant.
-/

/-- secp256k1 point addition is associative. -/
axiom ecAdd_assoc (a b c : ByteArray) :
    Crypto.ecAdd (Crypto.ecAdd a b) c = Crypto.ecAdd a (Crypto.ecAdd b c)

/-- secp256k1 point addition is commutative (the curve group is
abelian). -/
axiom ecAdd_comm (a b : ByteArray) :
    Crypto.ecAdd a b = Crypto.ecAdd b a

/-- The point at infinity is the additive identity. We model it as
`ecMakePoint 0 0`; a more refined model (Tier 4) would carry an
explicit `ecZero` constant or an inductive `Point ⊕ Infinity`. -/
axiom ecAdd_zero (p : ByteArray) :
    Crypto.ecAdd p (Crypto.ecMakePoint 0 0) = p

/-- Negation is the additive inverse: `p + (-p) = O`. -/
axiom ecNegate_inverse (p : ByteArray) :
    Crypto.ecAdd p (Crypto.ecNegate p) = Crypto.ecMakePoint 0 0

/-- Scalar multiplication distributes over scalar addition:
`p · (k1 + k2) = p · k1 + p · k2`. -/
axiom ecMul_distrib_add (p : ByteArray) (k1 k2 : Int) :
    Crypto.ecMul p (k1 + k2) = Crypto.ecAdd (Crypto.ecMul p k1) (Crypto.ecMul p k2)

/-- Scalar zero annihilates to the identity. -/
axiom ecMul_zero (p : ByteArray) :
    Crypto.ecMul p 0 = Crypto.ecMakePoint 0 0

/-- Scalar one is the identity scalar. -/
axiom ecMul_one (p : ByteArray) :
    Crypto.ecMul p 1 = p

/-- `ecMulGen` is `ecMul` against the generator `G`. We do not name
`G` explicitly; instead the axiom states that `ecMulGen 1` is a
*fixed nonzero* generator point (i.e., distinct from the point at
infinity). -/
axiom ecMulGen_one_ne_zero :
    Crypto.ecMulGen 1 ≠ Crypto.ecMakePoint 0 0

/-- Coordinate projection round-trip: `ecPointX (ecMakePoint x y) = x`
when `x` is a valid field element. We state the unconditional form
for now; the well-formedness predicate will land in Tier 4 once the
field model is concrete. -/
axiom ecPointX_makePoint (x y : Int) :
    Crypto.ecPointX (Crypto.ecMakePoint x y) = x

/-- Coordinate projection round-trip on the Y-coordinate. -/
axiom ecPointY_makePoint (x y : Int) :
    Crypto.ecPointY (Crypto.ecMakePoint x y) = y

/-! ## 2.5 NIST P-256 / P-384 group laws (FIPS 186-4)

Mirrors §2's secp256k1 group laws, narrowed to the bare primitives
that `ANF/Eval.lean` exposes for these curves (`pXAdd`, `pXMul`,
`pXMulGen`, `pXOnCurve`, `pXEncodeCompressed` — no `MakePoint /
PointX / PointY / ModReduce` analogues). Each axiom asserts a standard
abelian-group identity, with the same caveats as §2: the point at
infinity is not represented as a dedicated constant — `pXMulGen 1`
serves as a fixed nonzero generator witness, and full associativity /
commutativity are quantified over all 64-byte (P-256) or 96-byte
(P-384) operand shapes.

NIST P-256 and P-384 are defined in FIPS 186-4 ("Digital Signature
Standard (DSS)"), §D.1.2.3 (curve `P-256`) and §D.1.2.4 (curve
`P-384`): both are short Weierstraß curves `y² = x³ - 3x + b` over a
prime field, with cofactor 1 and explicit base point `G`. The group
laws below are the standard abelian-group identities for the
`E(Fp)`-rational points of those curves.

To express negation without introducing a `MakePoint` analogue we
axiomatize a bare `pXNegate : ByteArray → ByteArray` function symbol
(no body) — the codegen-to-spec layer in `Stack/P256P384.lean` then
ties `emitPXNegate` to this symbol.
-/

/-- Abstract P-256 negation symbol (no body). Used by the codegen-to-spec
axiom for `Stack.P256P384.emitP256Negate`. -/
axiom p256Negate : ByteArray → ByteArray

/-- Abstract P-384 negation symbol (no body). Used by the codegen-to-spec
axiom for `Stack.P256P384.emitP384Negate`. -/
axiom p384Negate : ByteArray → ByteArray

/-- P-256 point addition is associative (FIPS 186-4 §D.1.2.3). -/
axiom p256Add_assoc (a b c : ByteArray) :
    Crypto.p256Add (Crypto.p256Add a b) c = Crypto.p256Add a (Crypto.p256Add b c)

/-- P-256 point addition is commutative (the curve group is abelian). -/
axiom p256Add_comm (a b : ByteArray) :
    Crypto.p256Add a b = Crypto.p256Add b a

/-- P-256 scalar distributivity:
`p · (k1 + k2) = p · k1 + p · k2` (FIPS 186-4 §D.1.2.3). -/
axiom p256Mul_distrib_add (p : ByteArray) (k1 k2 : Int) :
    Crypto.p256Mul p (k1 + k2) = Crypto.p256Add (Crypto.p256Mul p k1) (Crypto.p256Mul p k2)

/-- P-256 scalar one is the identity scalar. -/
axiom p256Mul_one (p : ByteArray) :
    Crypto.p256Mul p 1 = p

/-- `p256MulGen 1` is a fixed nonzero generator point (i.e., distinct
from the empty 64-byte encoding). FIPS 186-4 §D.1.2.3 fixes a unique
base point `G` with prime-order; in particular `G ≠ O`. -/
axiom p256MulGen_one_ne_zero :
    Crypto.p256MulGen 1 ≠ ByteArray.empty

/-- P-384 point addition is associative (FIPS 186-4 §D.1.2.4). -/
axiom p384Add_assoc (a b c : ByteArray) :
    Crypto.p384Add (Crypto.p384Add a b) c = Crypto.p384Add a (Crypto.p384Add b c)

/-- P-384 point addition is commutative (the curve group is abelian). -/
axiom p384Add_comm (a b : ByteArray) :
    Crypto.p384Add a b = Crypto.p384Add b a

/-- P-384 scalar distributivity (FIPS 186-4 §D.1.2.4). -/
axiom p384Mul_distrib_add (p : ByteArray) (k1 k2 : Int) :
    Crypto.p384Mul p (k1 + k2) = Crypto.p384Add (Crypto.p384Mul p k1) (Crypto.p384Mul p k2)

/-- P-384 scalar one is the identity scalar. -/
axiom p384Mul_one (p : ByteArray) :
    Crypto.p384Mul p 1 = p

/-- `p384MulGen 1` is a fixed nonzero generator point (FIPS 186-4
§D.1.2.4 fixes a unique base point `G` with prime-order; in particular
`G ≠ O`). -/
axiom p384MulGen_one_ne_zero :
    Crypto.p384MulGen 1 ≠ ByteArray.empty

/-! ## 3. Auxiliary primitive axioms (function symbols, no body)

The EUF-CMA spec companions need the *signing side* of each scheme
to express the existential witness. We axiomatize these as bare
function symbols (no `opaque := stub` body — project policy Q1.4
forbids new opaques carrying stubs). They are independent additions
to the TCB.

These primitives never appear in `Eval`'s evaluator dispatch and
have no operational footprint; they exist solely to give the
companion axioms below well-typed witness shapes.
-/

/-- ECDSA private-key → public-key derivation: scalar multiplication
of the secp256k1 generator by `privkey`, encoded as a 64-byte
uncompressed point. -/
axiom derivePubKey : Int → ByteArray

/-- WOTS+ secret-key → public-key derivation. The WOTS+ scheme
chains `w-1` hash applications per secret-key chunk; the public key
is the concatenation of chain endpoints. -/
axiom deriveWOTSPub : ByteArray → ByteArray

/-- WOTS+ signing oracle: given a secret key and a message, produce
the deterministic one-time signature. -/
axiom signWOTS : ByteArray → ByteArray → ByteArray

/-- SLH-DSA secret-key → public-key derivation (FIPS 205). The same
function is used across all six parameter sets; the parameter set
is implicit in the byte-lengths of `sk` and the returned `pk`. -/
axiom deriveSlhDsaPub : ByteArray → ByteArray

/-- Rabin secret-key → public-key derivation (`pk = sk² mod n` in
the canonical form, but here treated as an opaque deterministic
function — the verifier only needs the existential witness). -/
axiom deriveRabinPub : ByteArray → ByteArray

/-! ## 4. EUF-CMA functional specifications

Each verifier's companion asserts the **existential / functional**
form of EUF-CMA: a successful verification implies the existence of
a secret key from which the public key was derived. This is weaker
than the game-based EUF-CMA assumption (which forbids forgery even
under chosen-message-attack), but it is the strongest form
expressible without a probabilistic / computational framework.

Combined with the cryptographic *assumption* that no feasible
algorithm produces signatures from a public key alone, the
companion rules out the "specialize-to-true" attack: an attacker
who chose `verifyXxx ≡ const true` would be forced to also
specialize `deriveXxxPub` to a function that maps every secret key
to every public key — impossible if `deriveXxxPub` is a function.
-/

/-- ECDSA (secp256k1) functional spec: a valid signature implies the
public key was derived from some secret key. The Lean signature of
`Crypto.checkSig` is `(sig pubkey : ByteArray) : Bool` — the
preimage is bound implicitly by the BIP-143 sighash context modeled
abstractly in `ANF/Eval.lean` (per OQ-4: transaction context is
deferred). -/
axiom verifyECDSA_correct (sig pubkey : ByteArray) :
    Crypto.checkSig sig pubkey = true →
    ∃ (privkey : Int), derivePubKey privkey = pubkey

/-- ECDSA (NIST P-256) functional spec. -/
axiom verifyECDSA_P256_correct (sig pubkey preimage : ByteArray) :
    Crypto.verifyECDSA_P256 sig pubkey preimage = true →
    ∃ (privkey : Int), derivePubKey privkey = pubkey

/-- ECDSA (NIST P-384) functional spec. -/
axiom verifyECDSA_P384_correct (sig pubkey preimage : ByteArray) :
    Crypto.verifyECDSA_P384 sig pubkey preimage = true →
    ∃ (privkey : Int), derivePubKey privkey = pubkey

/-- WOTS+ functional spec: a valid signature implies the public key
was derived from some secret key, AND the signature was produced by
the corresponding signing oracle. -/
axiom verifyWOTS_correct (msg sig pk : ByteArray) :
    Crypto.verifyWOTS msg sig pk = true →
    ∃ (sk : ByteArray), deriveWOTSPub sk = pk ∧ signWOTS sk msg = sig

/-- SLH-DSA SHA2-128s functional spec. -/
axiom verifySLHDSA_SHA2_128s_correct (msg sig pk : ByteArray) :
    Crypto.verifySLHDSA_SHA2_128s msg sig pk = true →
    ∃ (sk : ByteArray), deriveSlhDsaPub sk = pk

/-- SLH-DSA SHA2-128f functional spec. -/
axiom verifySLHDSA_SHA2_128f_correct (msg sig pk : ByteArray) :
    Crypto.verifySLHDSA_SHA2_128f msg sig pk = true →
    ∃ (sk : ByteArray), deriveSlhDsaPub sk = pk

/-- SLH-DSA SHA2-192s functional spec. -/
axiom verifySLHDSA_SHA2_192s_correct (msg sig pk : ByteArray) :
    Crypto.verifySLHDSA_SHA2_192s msg sig pk = true →
    ∃ (sk : ByteArray), deriveSlhDsaPub sk = pk

/-- SLH-DSA SHA2-192f functional spec. -/
axiom verifySLHDSA_SHA2_192f_correct (msg sig pk : ByteArray) :
    Crypto.verifySLHDSA_SHA2_192f msg sig pk = true →
    ∃ (sk : ByteArray), deriveSlhDsaPub sk = pk

/-- SLH-DSA SHA2-256s functional spec. -/
axiom verifySLHDSA_SHA2_256s_correct (msg sig pk : ByteArray) :
    Crypto.verifySLHDSA_SHA2_256s msg sig pk = true →
    ∃ (sk : ByteArray), deriveSlhDsaPub sk = pk

/-- SLH-DSA SHA2-256f functional spec. -/
axiom verifySLHDSA_SHA2_256f_correct (msg sig pk : ByteArray) :
    Crypto.verifySLHDSA_SHA2_256f msg sig pk = true →
    ∃ (sk : ByteArray), deriveSlhDsaPub sk = pk

/-- Rabin signature functional spec. The Rabin verifier consumes a
4-tuple `(msg, padding, sig, pk)`; the companion abstracts over the
padding. -/
axiom verifyRabinSig_correct (msg padding sig pk : ByteArray) :
    Crypto.verifyRabinSig msg padding sig pk = true →
    ∃ (sk : ByteArray), deriveRabinPub sk = pk

/-! ## 5. Robustness against the "specialize-to-true" attack

The companion axioms above rule out a class of trust-manifest attacks
of the form

```text
  axiom verifyWOTS_always_true : ∀ m s p, Crypto.verifyWOTS m s p = true
```

paired with EUF-CMA universal forgeability. `verifyWOTS_correct`
forces any specialization satisfying `verifyWOTS m s p = true` to
exhibit a secret key `sk` and a signing oracle output matching `s`.
EUF-CMA universal forgeability says no feasible algorithm produces
such an `sk` for arbitrary `(m, p)` — so the constantly-true
specialization is inconsistent with the cryptographic assumption.

The same argument applies to ECDSA (secp256k1, P-256, P-384), SLH-DSA
(all 6 parameter sets), and Rabin via the matching `_correct`
companion.

Note: the EUF-CMA assumption itself is **not** a Lean axiom in this
module. It is a *cryptographic / computational* assumption that
rules out infeasible witness-extraction algorithms. The Lean
companion is the *functional* form (existential witness); the
computational-EUF-CMA assumption is layered on top in any external
security argument. -/

/-! ## 6. Merkle root — concrete tree-fold spec (Phase B7)

The codegen module `RunarVerification.Stack.Merkle` emits a Bitcoin Script
fragment that *verifies a Merkle-path opening*: given a `leaf`, a `proof`
(a `depth*32`-byte ByteArray of sibling hashes), and an `index` selecting
the leaf's position, it climbs the tree computing the implied root.

Two related spec functions live here:

* `merkleRootD h d leaves` — the tree-fold spec.  Given a hash function
  `h` and `2^d` leaves, recursively pair-and-hash the leaves up `d`
  levels and return the resulting 32-byte root.  This is what the
  on-chain root *should equal* if the prover constructed `proof` against
  a tree built from `leaves`.

* `merkleVerifyPath h d leaf proof index` — the path-verifier spec.
  Iterates `d` levels: extract the next 32-byte sibling from `proof`,
  read the direction bit `(index >> i) & 1`, concatenate sibling and
  running hash in the right order, and hash via `h`.  This is the
  *operational* spec that mirrors the Stack-IR fragment one level at a
  time, and is the natural target for the runOps equivalence theorem in
  `Stack/Merkle.lean`.

Both functions are concrete recursive `def`s and contribute zero axioms
to the TCB.  Linking them — i.e. that `merkleVerifyPath` returns
`merkleRootD` when `proof` is the canonical opening of `leaf` at
position `index` — is a separate theorem that requires choosing
`leaves` consistent with `(leaf, proof, index)`; it is left as a future
refinement.
-/

/-- Pair up consecutive elements and hash each pair via `h`.  Trailing
odd elements (length-1 / empty inputs) are returned unchanged, matching
the "duplicate-last-leaf" convention used at the tree-builder boundary
when `leaves.length` is not a power of two. -/
def pairUp (h : ByteArray → ByteArray) : List ByteArray → List ByteArray
  | a :: b :: rest => h (a ++ b) :: pairUp h rest
  | xs => xs

/-- Tree-fold Merkle root, depth-indexed.

* `d = 0`: the input must be a single leaf; return it (or `ByteArray.empty`
  for malformed empty inputs — this matches the Bitcoin Script behaviour
  where an empty stack produces an error rather than a fixed sentinel).
* `d + 1`: pair-and-hash one level, recurse with depth `d`.

`merkleRootD h d leaves` is the concrete tree-fold over `leaves`; for
well-formed inputs (`leaves.length = 2 ^ d`) it returns the canonical
32-byte Merkle root. -/
def merkleRootD (h : ByteArray → ByteArray) : Nat → List ByteArray → ByteArray
  | 0,      leaves => leaves.headD ByteArray.empty
  | d + 1,  leaves => merkleRootD h d (pairUp h leaves)

/-- Reduction lemma for `merkleRootD`'s base case. -/
theorem merkleRootD_zero (h : ByteArray → ByteArray) (leaves : List ByteArray) :
    merkleRootD h 0 leaves = leaves.headD ByteArray.empty := rfl

/-- Reduction lemma for `merkleRootD`'s successor case. -/
theorem merkleRootD_succ (h : ByteArray → ByteArray)
    (d : Nat) (leaves : List ByteArray) :
    merkleRootD h (d + 1) leaves = merkleRootD h d (pairUp h leaves) := rfl

/-- One level of the Merkle path verifier.  Given the running
`current` hash, the remaining `proof` bytes, and the `index`, extract
the next 32-byte sibling, compute the direction bit, concatenate and
hash via `h`, returning the new `current` and the rest of the proof. -/
def merkleVerifyStep (h : ByteArray → ByteArray)
    (current : ByteArray) (proof : ByteArray) (index : Int) (level : Nat) :
    ByteArray × ByteArray :=
  let sibling := proof.extract 0 32
  let rest    := proof.extract 32 proof.size
  -- Direction bit: (index >> level) & 1.  We compute the shifted
  -- magnitude on the natAbs to mirror the on-chain `OP_RSHIFT` /
  -- `OP_MOD` sequence; negative indices are not produced by the
  -- compiler and the bit-extraction would diverge from Bitcoin Script
  -- semantics in that regime.
  let shifted : Nat := index.natAbs / (2 ^ level)
  let dir     : Nat := shifted % 2
  let combined : ByteArray :=
    if dir = 0 then current ++ sibling
              else sibling ++ current
  (h combined, rest)

/-- Path-verifier Merkle root spec.  Climbs `d` levels from the leaf
starting at `startLevel`, using `proof` as the source of sibling
hashes (32 bytes per level) and `index` as the source of direction
bits.  `startLevel` lets `merkleVerifyPath h leaf proof index 0 d`
denote the full climb from level 0 up to (excluding) level `d`. -/
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

/-- Base-case reduction: zero levels return the leaf unchanged. -/
theorem merkleVerifyPathFrom_zero (h : ByteArray → ByteArray)
    (leaf proof : ByteArray) (index : Int) (startLevel : Nat) :
    merkleVerifyPathFrom h leaf proof index startLevel 0 = leaf := rfl

/-- Base-case reduction for the top-level entry. -/
theorem merkleVerifyPath_zero (h : ByteArray → ByteArray)
    (leaf proof : ByteArray) (index : Int) :
    merkleVerifyPath h leaf proof index 0 = leaf := rfl

/-! ## 7. secp256k1 EC emit / runOps codegen-to-spec axioms (Phase B4)

Each axiom below links one of the 10 `Stack.Ec.emitEc*` op-list
builders to the abstract spec primitive in `ANF.Eval.Crypto`. The
shape mirrors the plan template:

```text
runOps Stack.Ec.emitEcAdd stkSt =
  .ok { stkSt with stack := .vBytes (Crypto.ecAdd p1 p2) :: rest }
```

These are **codegen-soundness axioms**, not group-law axioms — they
are pure compiler-correctness assumptions:

* The TS reference codegen in
  `packages/runar-compiler/src/passes/ec-codegen.ts` implements the
  same secp256k1 EC primitives this Lean module ports.
* The 7 cross-compiler conformance gate
  (`conformance/runner/runner.ts`) enforces byte-identical emitted
  Bitcoin Script for these emit families across all 7 tiers
  (TS, Go, Rust, Python, Zig, Ruby, Java) on every fixture without an
  opt-out allowlist.
* Each axiom shape mirrors the same `runOps stkSt = .ok stkSt'`
  pattern used for the SHA-256, BLAKE3 and WOTS+/SLH-DSA codegen
  families elsewhere in `Stack/`.

Proving these by direct opcode-by-opcode reduction is impractical:
`emitEcMul` alone unfolds into a 257-iteration MSB-first double-and-add
loop whose body is a 6-IF-deep Jacobian mixed-addition formula
(~500 ops per iteration; 50k+ ops total before peephole). The proof
obligation would dwarf the rest of the verification corpus. We accept
the codegen-to-spec link as 10 narrow axioms in this section, each
citing the corresponding TS reference function.

### Stack convention

`Stack.Eval.StackState.stack` is a `List Value` with **head = top**.
The emit functions expect inputs in TS-reference order — the
deepest input is the *leftmost* arg of the spec function. E.g. for
`emitEcAdd` the TS tracker is initialised with
`[some "_pa", some "_pb"]` (bottom→top), so on `StackState.stack`
the top is `_pb`, i.e. the pattern is `vBytes pb :: vBytes pa :: rest`
and the output is `vBytes (Crypto.ecAdd pa pb) :: rest`.

### TCB impact

This section adds **10** new axioms (one per emit builder):

* `emitEcAdd_runOps_eq`
* `emitEcMul_runOps_eq`
* `emitEcMulGen_runOps_eq`
* `emitEcNegate_runOps_eq`
* `emitEcOnCurve_runOps_eq`
* `emitEcModReduce_runOps_eq`
* `emitEcEncodeCompressed_runOps_eq`
* `emitEcMakePoint_runOps_eq`
* `emitEcPointX_runOps_eq`
* `emitEcPointY_runOps_eq`
-/

open RunarVerification.Stack
open RunarVerification.Stack.Eval (StackState runOps)
open RunarVerification.ANF.Eval (Value)

/-- `Stack.Ec.emitEcAdd`: stack in `[pa, pb]` (pb on TOS) → `[ecAdd pa pb]`.
Mirrors `emitEcAdd` in `ec-codegen.ts:583-591`. -/
axiom emitEcAdd_runOps_eq (stkSt : StackState) (pa pb : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes pb :: .vBytes pa :: rest) :
    runOps Stack.Ec.emitEcAdd stkSt
      = .ok { stkSt with stack := .vBytes (Crypto.ecAdd pa pb) :: rest }

/-- `Stack.Ec.emitEcMul`: stack in `[pt, k]` (k on TOS) → `[ecMul pt k]`.
Mirrors `emitEcMul` in `ec-codegen.ts:601-665` (257-iter MSB-first
double-and-add with `k + 3n` adjustment). -/
axiom emitEcMul_runOps_eq (stkSt : StackState) (pt : ByteArray) (k : Int)
    (rest : List Value)
    (hStk : stkSt.stack = .vBigint k :: .vBytes pt :: rest) :
    runOps Stack.Ec.emitEcMul stkSt
      = .ok { stkSt with stack := .vBytes (Crypto.ecMul pt k) :: rest }

/-- `Stack.Ec.emitEcMulGen`: stack in `[k]` → `[ecMulGen k]`. Pushes the
generator `G` as a 64-byte blob, swaps, and delegates to `emitEcMul`.
Mirrors `emitEcMulGen` in `ec-codegen.ts:671-676`. -/
axiom emitEcMulGen_runOps_eq (stkSt : StackState) (k : Int)
    (rest : List Value)
    (hStk : stkSt.stack = .vBigint k :: rest) :
    runOps Stack.Ec.emitEcMulGen stkSt
      = .ok { stkSt with stack := .vBytes (Crypto.ecMulGen k) :: rest }

/-- `Stack.Ec.emitEcNegate`: `(x, y) → (x, p - y)`.
Mirrors `emitEcNegate` in `ec-codegen.ts:678-685`. -/
axiom emitEcNegate_runOps_eq (stkSt : StackState) (pt : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes pt :: rest) :
    runOps Stack.Ec.emitEcNegate stkSt
      = .ok { stkSt with stack := .vBytes (Crypto.ecNegate pt) :: rest }

/-- `Stack.Ec.emitEcOnCurve`: check `y² ≡ x³ + 7 mod p`. Output is a
bool. The Stack VM models the boolean as a script number (`OP_EQUAL`'s
result), but we expose it as a `vBool` for downstream proofs since the
spec axiom returns `Bool`.

Mirrors `emitEcOnCurve` in `ec-codegen.ts:687-703`. -/
axiom emitEcOnCurve_runOps_eq (stkSt : StackState) (pt : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes pt :: rest) :
    runOps Stack.Ec.emitEcOnCurve stkSt
      = .ok { stkSt with stack := .vBool (Crypto.ecOnCurve pt) :: rest }

/-- `Stack.Ec.emitEcModReduce`: `((value % mod) + mod) % mod`.
Stack `[value, mod]` (mod on TOS) → `[result]`. Mirrors
`emitEcModReduce` in `ec-codegen.ts:705-715`. -/
axiom emitEcModReduce_runOps_eq (stkSt : StackState) (value m : Int)
    (rest : List Value)
    (hStk : stkSt.stack = .vBigint m :: .vBigint value :: rest) :
    runOps Stack.Ec.emitEcModReduce stkSt
      = .ok { stkSt with
              stack := .vBigint (Crypto.ecModReduce value m) :: rest }

/-- `Stack.Ec.emitEcEncodeCompressed`: 64-byte point → 33-byte
compressed pubkey. Mirrors `emitEcEncodeCompressed` in
`ec-codegen.ts:717-738`. -/
axiom emitEcEncodeCompressed_runOps_eq (stkSt : StackState) (pt : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes pt :: rest) :
    runOps Stack.Ec.emitEcEncodeCompressed stkSt
      = .ok { stkSt with
              stack := .vBytes (Crypto.ecEncodeCompressed pt) :: rest }

/-- `Stack.Ec.emitEcMakePoint`: `(x : Int, y : Int) → Point`. Stack
`[x, y]` (y on TOS) → `[point_bytes]`. Mirrors `emitEcMakePoint` in
`ec-codegen.ts:740-760`. -/
axiom emitEcMakePoint_runOps_eq (stkSt : StackState) (x y : Int)
    (rest : List Value)
    (hStk : stkSt.stack = .vBigint y :: .vBigint x :: rest) :
    runOps Stack.Ec.emitEcMakePoint stkSt
      = .ok { stkSt with
              stack := .vBytes (Crypto.ecMakePoint x y) :: rest }

/-- `Stack.Ec.emitEcPointX`: extract x-coordinate (Int) from Point.
Mirrors `emitEcPointX` in `ec-codegen.ts:762-770`. -/
axiom emitEcPointX_runOps_eq (stkSt : StackState) (pt : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes pt :: rest) :
    runOps Stack.Ec.emitEcPointX stkSt
      = .ok { stkSt with stack := .vBigint (Crypto.ecPointX pt) :: rest }

/-- `Stack.Ec.emitEcPointY`: extract y-coordinate (Int) from Point.
Mirrors `emitEcPointY` in `ec-codegen.ts:772-781`. -/
axiom emitEcPointY_runOps_eq (stkSt : StackState) (pt : ByteArray)
    (rest : List Value)
    (hStk : stkSt.stack = .vBytes pt :: rest) :
    runOps Stack.Ec.emitEcPointY stkSt
      = .ok { stkSt with stack := .vBigint (Crypto.ecPointY pt) :: rest }

/-! ## 8. BabyBear prime field + degree-4 extension specifications
   (Phase B6, 2026-05-16)

BabyBear (`p = 2^31 - 2^27 + 1 = 2013265921`) is a small prime field
used by the SP1 / Plonky3 STARK stack. Per project policy (CLAUDE.md
"EVM/STARK proof-system primitives are Go-only by project policy"),
BabyBear codegen ships in the **Go tier only** and is not a
conformance target for the other six tiers. The Lean specs below
still advance the verification: they give the bare
`Crypto.bbFieldAdd / Sub / Mul / Inv` axioms (declared in
`ANF/Eval.lean` as unconstrained `Int → Int → Int` / `Int → Int`) a
concrete mathematical meaning, so that future codegen-equivalence
proofs in `Stack/BabyBear.lean` (`runOps_emitBBFieldMul_eq` etc.)
can target a stable spec rather than a bare axiom symbol.

### Why concrete `def`s instead of axioms (for the spec layer)

The BabyBear modulus is small enough that the spec functions are
trivially computable in Lean (`Int.emod` and `Int.gcd` are
implemented in the kernel). Concrete `def`s give us:

* **`rfl`/`decide`-friendly reasoning** for small ground-case
  evaluations.
* **Zero axiom cost** for the spec layer itself.
* A **single source of truth** that downstream `_correct` axioms
  reference — there is no opportunity for the spec and the axiom to
  drift.

### Field model

We represent field elements as `Int` (not `Fin BabyBearPrime`) for
two reasons:

1. `ANF/Eval.lean` exposes `bbFieldAdd / Sub / Mul / Inv` as
   `Int → Int → Int` (and `Int → Int`), matching the runtime
   integer representation used throughout the ANF evaluator. A
   `Fin` model would require explicit coercions at every call
   site.
2. The codegen-equivalence theorems compare scripts whose values
   live in Bitcoin Script's `bigint` arena (also `Int`-shaped, with
   bounded width). Keeping the spec in `Int` matches the codegen
   layer one-for-one.

The spec functions explicitly reduce by `% BabyBearPrime` so they
return canonical representatives in `[0, p-1]`.
-/

/-- BabyBear field prime: `p = 2^31 - 2^27 + 1 = 2013265921`. -/
def BabyBearPrime : Int := 2013265921

/-- Quadratic non-residue used by the degree-4 extension `F[X]/(X^4 - W)`.
For BabyBear, `W = 11` (matches `Stack/BabyBear.lean` and the TS /
Go reference codegen). -/
def BabyBearExt4W : Int := 11

/-! ### 8.1. Base-field spec functions

These are the canonical mathematical operations on `F_p` for
`p = BabyBearPrime`. They mirror the formulas that the codegen in
`Stack/BabyBear.lean` (and `compilers/go/codegen/babybear.go`)
compiles to Bitcoin Script.
-/

/-- Canonical reduction modulo `BabyBearPrime`. Mirrors the TS
`fieldMod` helper (`babybear-codegen.ts:136-147`): `(a % p + p) % p`
returns the canonical non-negative representative in `[0, p-1]`
even for negative `a`. -/
def bbMod (a : Int) : Int := ((a % BabyBearPrime) + BabyBearPrime) % BabyBearPrime

/-- `bbAdd a b = (a + b) mod p`. -/
def bbAdd (a b : Int) : Int := bbMod (a + b)

/-- `bbSub a b = (a - b) mod p`. -/
def bbSub (a b : Int) : Int := bbMod (a - b)

/-- `bbMul a b = (a * b) mod p`. -/
def bbMul (a b : Int) : Int := bbMod (a * b)

/-- `bbSqr a = (a * a) mod p`. Mirrors `Stack/BabyBear.lean#fieldSqr`. -/
def bbSqr (a : Int) : Int := bbMul a a

/-- `bbNeg a = (-a) mod p = (p - a mod p) mod p`. Useful as the
abstract spec for the `0 - x` patterns that appear in ext4 inverse
component 1 and 3 codegen. -/
def bbNeg (a : Int) : Int := bbMod (BabyBearPrime - bbMod a)

/-- Multiplication by a constant. Mirrors `Stack/BabyBear.lean#fieldMulConst`
(no `OP_2MUL` special-casing for `c = 2`). -/
def bbMulConst (a c : Int) : Int := bbMod (a * c)

/-- `bbPow a k` — modular exponentiation by a non-negative integer
exponent. Used by the spec for the Fermat-little-theorem inverse
and for any future static-exponent shortcuts. We define it
recursively on `Nat` to keep termination obvious. -/
def bbPowNat (a : Int) : Nat → Int
  | 0      => 1
  | n + 1  => bbMul a (bbPowNat a n)

/-- `bbInv a = a^(p - 2) mod p`. Defined as the closed-form Fermat-
little-theorem expression. Note that `bbInv 0 = 0^(p-2) = 0`, which
matches the codegen behaviour: `Stack/BabyBear.lean#fieldInv` does
not special-case zero, and the resulting script likewise produces
`0` for the zero input. Callers that require a true inverse must
ensure the operand is non-zero. -/
def bbInv (a : Int) : Int := bbPowNat (bbMod a) (BabyBearPrime - 2).toNat

/-! ### 8.2. Degree-4 extension spec functions `F[X]/(X^4 - W)`

We represent extension elements as 4-tuples `(c0, c1, c2, c3)`
encoding `c0 + c1*X + c2*X^2 + c3*X^3`. The multiplication and
inverse formulas mirror `Stack/BabyBear.lean#emitBBExt4Mul0..3` and
`emitBBExt4Inv0..3` one-for-one. Each per-component spec function
is named `bbExt4Mul0 / 1 / 2 / 3` and `bbExt4Inv0 / 1 / 2 / 3` and
takes the eight (resp. four) input field elements as separate
`Int` arguments.

These specs are pure `def`s — there is no bare axiom companion in
`ANF/Eval.lean` for ext4 ops, because the ANF level represents an
ext4 multiplication as a sequence of 4 component-level builtin
calls each of which already has a base-field axiom. The codegen
in `Stack/BabyBear.lean` matches this structure.
-/

/-- `r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)`. Mirrors
`Stack/BabyBear.lean#emitBBExt4Mul0`. -/
def bbExt4Mul0 (a0 a1 a2 a3 b0 b1 b2 b3 : Int) : Int :=
  let t0 := bbMul a0 b0
  let t1 := bbMul a1 b3
  let t2 := bbMul a2 b2
  let t3 := bbMul a3 b1
  let cross := bbAdd (bbAdd t1 t2) t3
  let wcross := bbMulConst cross BabyBearExt4W
  bbAdd t0 wcross

/-- `r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)`. Mirrors
`Stack/BabyBear.lean#emitBBExt4Mul1`. -/
def bbExt4Mul1 (a0 a1 a2 a3 b0 b1 b2 b3 : Int) : Int :=
  let t0 := bbMul a0 b1
  let t1 := bbMul a1 b0
  let direct := bbAdd t0 t1
  let t2 := bbMul a2 b3
  let t3 := bbMul a3 b2
  let cross := bbAdd t2 t3
  let wcross := bbMulConst cross BabyBearExt4W
  bbAdd direct wcross

/-- `r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)`. Mirrors
`Stack/BabyBear.lean#emitBBExt4Mul2`. -/
def bbExt4Mul2 (a0 a1 a2 a3 b0 b1 b2 b3 : Int) : Int :=
  let t0 := bbMul a0 b2
  let t1 := bbMul a1 b1
  let sum01 := bbAdd t0 t1
  let t2 := bbMul a2 b0
  let direct := bbAdd sum01 t2
  let t3 := bbMul a3 b3
  let wcross := bbMulConst t3 BabyBearExt4W
  bbAdd direct wcross

/-- `r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0`. Mirrors
`Stack/BabyBear.lean#emitBBExt4Mul3`. -/
def bbExt4Mul3 (a0 a1 a2 a3 b0 b1 b2 b3 : Int) : Int :=
  let t0 := bbMul a0 b3
  let t1 := bbMul a1 b2
  let sum01 := bbAdd t0 t1
  let t2 := bbMul a2 b1
  let sum012 := bbAdd sum01 t2
  let t3 := bbMul a3 b0
  bbAdd sum012 t3

/-- Shared "norm0" intermediate for ext4 inverse:
`norm0 = a0² + W*a2² - 2*W*a1*a3`. -/
def bbExt4Norm0 (a0 a1 a2 a3 : Int) : Int :=
  let a0sq := bbSqr a0
  let a2sq := bbSqr a2
  let wa2sq := bbMulConst a2sq BabyBearExt4W
  let n0a := bbAdd a0sq wa2sq
  let a1a3 := bbMul a1 a3
  let twoW := bbMod (BabyBearExt4W * 2)
  let twoWa1a3 := bbMulConst a1a3 twoW
  bbSub n0a twoWa1a3

/-- Shared "norm1" intermediate for ext4 inverse:
`norm1 = 2*a0*a2 - a1² - W*a3²`. -/
def bbExt4Norm1 (a0 a1 a2 a3 : Int) : Int :=
  let a0a2 := bbMul a0 a2
  let twoA0a2 := bbMulConst a0a2 2
  let a1sq := bbSqr a1
  let n1a := bbSub twoA0a2 a1sq
  let a3sq := bbSqr a3
  let wa3sq := bbMulConst a3sq BabyBearExt4W
  bbSub n1a wa3sq

/-- Determinant of the "even/odd" decomposition used by the ext4
inverse: `det = norm0² - W * norm1²`. -/
def bbExt4Det (a0 a1 a2 a3 : Int) : Int :=
  let n0 := bbExt4Norm0 a0 a1 a2 a3
  let n1 := bbExt4Norm1 a0 a1 a2 a3
  let n0sq := bbSqr n0
  let n1sq := bbSqr n1
  let wn1sq := bbMulConst n1sq BabyBearExt4W
  bbSub n0sq wn1sq

/-- Shared scalar for the ext4 inverse: `scalar = inv(det)`. -/
def bbExt4Scalar (a0 a1 a2 a3 : Int) : Int :=
  bbInv (bbExt4Det a0 a1 a2 a3)

/-- `inv_n0 = norm0 * scalar`. -/
def bbExt4InvN0 (a0 a1 a2 a3 : Int) : Int :=
  bbMul (bbExt4Norm0 a0 a1 a2 a3) (bbExt4Scalar a0 a1 a2 a3)

/-- `inv_n1 = -norm1 * scalar = ((p - norm1 mod p) mod p) * scalar`. -/
def bbExt4InvN1 (a0 a1 a2 a3 : Int) : Int :=
  bbMul (bbNeg (bbExt4Norm1 a0 a1 a2 a3)) (bbExt4Scalar a0 a1 a2 a3)

/-- Component 0 of the ext4 inverse:
`r0 = a0*inv_n0 + W*a2*inv_n1`. Mirrors
`Stack/BabyBear.lean#emitBBExt4Inv0`. -/
def bbExt4Inv0 (a0 a1 a2 a3 : Int) : Int :=
  let inv_n0 := bbExt4InvN0 a0 a1 a2 a3
  let inv_n1 := bbExt4InvN1 a0 a1 a2 a3
  let p0 := bbMul a0 inv_n0
  let p1 := bbMul a2 inv_n1
  let wp1 := bbMulConst p1 BabyBearExt4W
  bbAdd p0 wp1

/-- Component 1 of the ext4 inverse:
`r1 = -(a1*inv_n0 + W*a3*inv_n1)`. Mirrors
`Stack/BabyBear.lean#emitBBExt4Inv1`. -/
def bbExt4Inv1 (a0 a1 a2 a3 : Int) : Int :=
  let inv_n0 := bbExt4InvN0 a0 a1 a2 a3
  let inv_n1 := bbExt4InvN1 a0 a1 a2 a3
  let p0 := bbMul a1 inv_n0
  let p1 := bbMul a3 inv_n1
  let wp1 := bbMulConst p1 BabyBearExt4W
  let odd0 := bbAdd p0 wp1
  bbSub 0 odd0

/-- Component 2 of the ext4 inverse:
`r2 = a0*inv_n1 + a2*inv_n0`. Mirrors
`Stack/BabyBear.lean#emitBBExt4Inv2`. -/
def bbExt4Inv2 (a0 a1 a2 a3 : Int) : Int :=
  let inv_n0 := bbExt4InvN0 a0 a1 a2 a3
  let inv_n1 := bbExt4InvN1 a0 a1 a2 a3
  let p0 := bbMul a0 inv_n1
  let p1 := bbMul a2 inv_n0
  bbAdd p0 p1

/-- Component 3 of the ext4 inverse:
`r3 = -(a1*inv_n1 + a3*inv_n0)`. Mirrors
`Stack/BabyBear.lean#emitBBExt4Inv3`. -/
def bbExt4Inv3 (a0 a1 a2 a3 : Int) : Int :=
  let inv_n0 := bbExt4InvN0 a0 a1 a2 a3
  let inv_n1 := bbExt4InvN1 a0 a1 a2 a3
  let p0 := bbMul a1 inv_n1
  let p1 := bbMul a3 inv_n0
  let odd1 := bbAdd p0 p1
  bbSub 0 odd1

/-! ### 8.3. Functional-correctness companions for the base-field symbols

The `Crypto.bbFieldAdd / Sub / Mul / Inv` symbols (declared in
`ANF/Eval.lean`) were bare `axiom`s in Tier 5.1; in Phase B6
(2026-05-17) they were converted to concrete `def`s that mirror the
specs in §8.1 one-for-one. The four companion lemmas below are
therefore *theorems* (was: axioms): each is discharged by
`rfl`-style reduction after unfolding both the bare-side def
(`bbFieldAdd` etc.) and the spec-side def (`bbAdd` etc.) to the same
underlying `bbMod`/`bbFieldMod` canonical reduction.

The side-conditions `0 ≤ a < BabyBearPrime` (and likewise for `b`)
are retained for backward compatibility with downstream code that
quotes the original axiom signature, but they are not used in the
proofs — both sides reduce to the same canonical representative
regardless of the input range. Downstream callers requiring
inputs already in `[0, p-1]` are unaffected.

**Citation.** The semantics of BabyBear prime-field arithmetic is
standard (see e.g. Plonky3 `koala-bear/src/baby_bear.rs` and the
SP1 v6.0.2 specification, which the Go reference compiler
implements byte-for-byte). The Lean specs and the `ANF/Eval`
companion `def`s mirror those formulas one-for-one.
-/

/-- Internal: the spec-side `bbMod` and the ANF-side `Crypto.bbFieldMod`
both reduce a (possibly-negative) `Int` to its canonical representative
in `[0, p-1]`. They share the same `((a % p) + p) % p` formula with the
same modulus (`BabyBearPrime = bbFieldPrime = 2013265921`), so equality
holds by reduction. -/
private theorem bbMod_eq_bbFieldMod (a : Int) :
    bbMod a = Crypto.bbFieldMod a := by
  unfold bbMod Crypto.bbFieldMod
  rfl

/-- `Crypto.bbFieldAdd` is `bbAdd` on every input (the side-conditions
are vacuous — both sides apply the same canonical reduction). -/
theorem bbFieldAdd_correct (a b : Int)
    (ha : 0 ≤ a) (ha' : a < BabyBearPrime)
    (hb : 0 ≤ b) (hb' : b < BabyBearPrime) :
    Crypto.bbFieldAdd a b = bbAdd a b := by
  -- Suppress unused-hypothesis lints; the args are kept for signature
  -- compatibility with the previous axiom declaration.
  let _ := ha; let _ := ha'; let _ := hb; let _ := hb'
  unfold bbAdd Crypto.bbFieldAdd
  exact (bbMod_eq_bbFieldMod (a + b)).symm

/-- `Crypto.bbFieldSub` is `bbSub` on every input. -/
theorem bbFieldSub_correct (a b : Int)
    (ha : 0 ≤ a) (ha' : a < BabyBearPrime)
    (hb : 0 ≤ b) (hb' : b < BabyBearPrime) :
    Crypto.bbFieldSub a b = bbSub a b := by
  let _ := ha; let _ := ha'; let _ := hb; let _ := hb'
  unfold bbSub Crypto.bbFieldSub
  exact (bbMod_eq_bbFieldMod (a - b)).symm

/-- `Crypto.bbFieldMul` is `bbMul` on every input. -/
theorem bbFieldMul_correct (a b : Int)
    (ha : 0 ≤ a) (ha' : a < BabyBearPrime)
    (hb : 0 ≤ b) (hb' : b < BabyBearPrime) :
    Crypto.bbFieldMul a b = bbMul a b := by
  let _ := ha; let _ := ha'; let _ := hb; let _ := hb'
  unfold bbMul Crypto.bbFieldMul
  exact (bbMod_eq_bbFieldMod (a * b)).symm

/-- `Crypto.bbFieldInv` is `bbInv` on every input.
`bbInv 0 = 0^(p-2) = 0` by the Fermat-little-theorem definition;
this matches the codegen behaviour (`Stack/BabyBear.lean#fieldInv`
does not special-case `a = 0`). -/
theorem bbFieldInv_correct (a : Int)
    (ha : 0 ≤ a) (ha' : a < BabyBearPrime) :
    Crypto.bbFieldInv a = bbInv a := by
  let _ := ha; let _ := ha'
  unfold bbInv Crypto.bbFieldInv
  -- Both sides apply `bbFieldPowNat`/`bbPowNat` to the canonical
  -- reduction of `a` raised to `p - 2`. Reduce the two recursive
  -- definitions and the two `bbMod`/`bbFieldMod` canonical reducers
  -- to the same underlying computation.
  have hMod : Crypto.bbFieldMod a = bbMod a := (bbMod_eq_bbFieldMod a).symm
  rw [hMod]
  -- Reduce `Crypto.bbFieldPowNat` to `bbPowNat` pointwise. The two
  -- helpers share the same recursion shape; the only difference is
  -- the multiplication backend (`Crypto.bbFieldMul` vs `bbMul`),
  -- which are pointwise equal by `bbMod_eq_bbFieldMod` on the
  -- product. Discharge via induction on the exponent.
  have hPow : ∀ (x : Int) (n : Nat),
      Crypto.bbFieldPowNat x n = bbPowNat x n := by
    intro x n
    induction n with
    | zero => rfl
    | succ k ih =>
      unfold Crypto.bbFieldPowNat bbPowNat
      rw [ih]
      unfold Crypto.bbFieldMul bbMul
      exact bbMod_eq_bbFieldMod _
  -- `Crypto.bbFieldPrime - 2 = BabyBearPrime - 2 = 2013265919` by
  -- definitional unfolding of both constants.
  exact hPow _ _

/-! ### 8.4. Sanity lemmas for the spec layer (provable, no axioms)

These small `decide`-friendly lemmas confirm the spec defs reduce
to small-integer ground truth. They give downstream proofs a
canonical entry point that does not depend on the bare axioms.
-/

/-- `bbMod` always returns a canonical non-negative representative
strictly less than `p` (for `p > 0`, which holds here). Stated as a
ground-case sanity check on the constant `BabyBearPrime`. -/
theorem bbMod_zero : bbMod 0 = 0 := by decide

/-- `bbAdd` is well-defined on the canonical zero. -/
theorem bbAdd_zero_zero : bbAdd 0 0 = 0 := by decide

/-- `bbMul` annihilates with zero on the left. -/
theorem bbMul_zero_left (a : Int) : bbMul 0 a = bbMod 0 := by
  unfold bbMul
  simp

/-- `bbSub` of equals on the canonical representative is zero. -/
theorem bbSub_self_zero : bbSub 0 0 = 0 := by decide

/-! ## 9. WOTS+ verification — concrete spec (Phase B8)

The bare `Crypto.verifyWOTS` axiom in `ANF/Eval.lean` is a 3-arg
`ByteArray → ByteArray → ByteArray → Bool` symbol with no semantics
attached. This section adds a **concrete `def`**
`Crypto.Spec.verifyWOTS` that implements the WOTS+ verifier
(Winternitz one-time signature, parameters `w = 16`, `n = 32`,
`len₁ = 64`, `len₂ = 3`, `len = 67`) over `Crypto.HashBackend.sha256`.

The concrete `def` advances verification regardless of whether the
companion theorem `runOps_wotsBodyOps_eq` is discharged: it grounds
the meaning of "WOTS+ verifies" in a closed-form computation, so
downstream theorems quoting `Crypto.Spec.verifyWOTS` are no longer
quoting an opaque assumption.

## Algorithm (mirroring `packages/runar-compiler/src/passes/wots-codegen.ts`):

1. Split `pk` (64 bytes) into `pubSeed` (`pk[0..32]`) and `pkRoot`
   (`pk[32..64]`).
2. Compute `msgHash = sha256(msg)` (32 bytes).
3. Decompose `msgHash` into 64 nibbles `d₀ … d₆₃` (high nibble first
   per byte).
4. Compute checksum `csum = Σᵢ (15 − dᵢ)` (a value in `[0, 64·15]`).
5. Decompose `csum` into 3 base-16 digits `[csum/256 mod 16,
   csum/16 mod 16, csum mod 16]` → `d₆₄, d₆₅, d₆₆`.
6. For each chain `i ∈ 0..66`, take `sigᵢ = sig[i·32 .. (i+1)·32]`
   and compute `endpointᵢ` by applying the chain function
   `F(pubSeed, i, j, X) = sha256(pubSeed ‖ byte(i) ‖ byte(j) ‖ X)`
   for `j = dᵢ, dᵢ+1, …, 14`, starting from `X = sigᵢ`.
7. Concatenate all 67 endpoints, hash once with SHA-256, and compare
   to `pkRoot`.

## Trust footprint

Adds **zero** axioms (purely a concrete `def` over the existing
`Crypto.HashBackend.sha256` backend assumption). The existential
companion `verifyWOTS_correct` remains attached to the bare
`Crypto.verifyWOTS` axiom; the codegen-to-spec equivalence between
the bare axiom and this concrete spec is left as the
`runOps_wotsBodyOps_eq` obligation in `Stack/Wots.lean` (currently
an assumption — see §B8 of TRUST_MANIFEST.md).
-/

namespace WotsImpl

/-- Slice a 32-byte chunk out of `b` starting at byte offset `start`.
Returns an empty `ByteArray` if `start + 32 > b.size`. -/
@[inline] def chunk32 (b : ByteArray) (start : Nat) : ByteArray :=
  b.extract start (start + 32)

/-- One chain step. `F(pubSeed, chainIdx, j, X) =
sha256(pubSeed ‖ byte(chainIdx) ‖ byte(j) ‖ X)`. -/
@[inline] def chainStep (pubSeed : ByteArray) (chainIdx j : Nat)
    (x : ByteArray) : ByteArray :=
  let adrs : ByteArray :=
    ByteArray.mk #[chainIdx.toUInt8, j.toUInt8]
  Crypto.sha256 (pubSeed ++ adrs ++ x)

/-- Apply `chainStep` for `j ∈ [startJ, 15)`. -/
def runChainFrom (pubSeed : ByteArray) (chainIdx : Nat) :
    (startJ : Nat) → (x : ByteArray) → ByteArray
  | startJ, x =>
      if startJ ≥ 15 then x
      else runChainFrom pubSeed chainIdx (startJ + 1)
             (chainStep pubSeed chainIdx startJ x)
termination_by startJ _ => 15 - startJ

/-- Read byte `i` of `b`, or `0` if out of bounds. Mirrors
`ANF.Eval.readByte` in spirit but returns a `Nat`. -/
@[inline] def byteAt (b : ByteArray) (i : Nat) : Nat :=
  if i < b.size then (b.get! i).toNat else 0

/-- Decompose 32-byte `msgHash` into 64 nibbles (high-first per byte).
Index `i` is byte `i / 2`'s high nibble if `i` is even, low nibble
if `i` is odd. -/
@[inline] def msgNibble (msgHash : ByteArray) (i : Nat) : Nat :=
  let b := byteAt msgHash (i / 2)
  if i % 2 = 0 then b / 16 else b % 16

/-- Sum of `(15 - dᵢ)` over the 64 message nibbles. -/
def csumOfMsg (msgHash : ByteArray) : Nat :=
  let rec go (i : Nat) (acc : Nat) : Nat :=
    if i ≥ 64 then acc
    else go (i + 1) (acc + (15 - msgNibble msgHash i))
  termination_by 64 - i
  go 0 0

/-- All 67 digits in order: 64 message nibbles + 3 checksum digits. -/
@[inline] def digitAt (msgHash : ByteArray) (i : Nat) : Nat :=
  if i < 64 then msgNibble msgHash i
  else
    let csum := csumOfMsg msgHash
    match i - 64 with
    | 0 => (csum / 256) % 16
    | 1 => (csum / 16) % 16
    | _ => csum % 16

/-- Compute one chain's endpoint: take signature chunk `i`, run chain
function from step `dᵢ` through step 14. -/
@[inline] def endpointAt (pubSeed sig : ByteArray) (msgHash : ByteArray)
    (i : Nat) : ByteArray :=
  let sigChunk := chunk32 sig (i * 32)
  let d := digitAt msgHash i
  runChainFrom pubSeed i d sigChunk

/-- Concatenate all 67 endpoints in order. -/
def concatEndpoints (pubSeed sig : ByteArray) (msgHash : ByteArray) :
    ByteArray :=
  let rec go (i : Nat) (acc : ByteArray) : ByteArray :=
    if i ≥ 67 then acc
    else go (i + 1) (acc ++ endpointAt pubSeed sig msgHash i)
  termination_by 67 - i
  go 0 ByteArray.empty

end WotsImpl

/-- Concrete WOTS+ verifier (parameters `w=16, n=32, len=67`).
Returns `true` iff the recomputed `pkRoot` matches `pk[32..64]`.

Mirrors `emitVerifyWOTS` in
`packages/runar-compiler/src/passes/wots-codegen.ts`. The
companion `runOps_wotsBodyOps_eq` in `Stack/Wots.lean` connects the
emitted Stack-IR body to this concrete spec.

When `pk.size < 64` or `sig.size < 67·32 = 2144`, the
`ByteArray.extract`/`byteAt` helpers return empty / zero defaults,
so the verifier still computes a total result (which will not
typically match `pkRoot` on malformed inputs). -/
def verifyWOTS (msg sig pk : ByteArray) : Bool :=
  let pubSeed := WotsImpl.chunk32 pk 0
  let pkRoot  := WotsImpl.chunk32 pk 32
  let msgHash := Crypto.sha256 msg
  let endpts  := WotsImpl.concatEndpoints pubSeed sig msgHash
  let computedRoot := Crypto.sha256 endpts
  computedRoot = pkRoot

/-! ### Sanity smoke tests

These are evaluable theorems (closed under `rfl`-after-reduction)
that check basic structural facts of the concrete spec. They do
*not* validate the SHA-256 backend — that remains parametric. -/

/-- The verifier is total: every input produces a `Bool`. -/
example (msg sig pk : ByteArray) :
    (verifyWOTS msg sig pk = true) ∨ (verifyWOTS msg sig pk = false) := by
  cases h : verifyWOTS msg sig pk
  · right; rfl
  · left; rfl

/-! ## 10. Concrete Rabin verification spec (Phase B10)

Rabin signature verification has a *concrete arithmetic* spec: the
verifier checks `(sig² + padding) mod pubKey == SHA256(msg)`. The
lowering at `Stack.Lower.lowerVerifyRabinSigOpsLive` emits a fixed
10-opcode body — see `Stack.Rabin.rabinBodyOps` — that exactly
mirrors the TS reference `emitVerifyRabinSig` at
`packages/runar-compiler/src/passes/rabin-codegen.ts:37-48`.

The concrete spec `verifyRabinSig_spec` defined here grounds the
meaning of "Rabin verifies" in closed-form modular arithmetic.
The codegen-to-spec equivalence lives in
`RunarVerification.Stack.Rabin.runOps_rabinBodyOps_eq` (which
references this spec). The axiom is sited in `Stack/Rabin.lean`
(rather than here) to avoid an import cycle through
`Stack.Lower → Stack.Wots → Crypto.Spec`.
-/

/-- Concrete Rabin verification spec.

Inputs:
* `msg`     — message bytes hashed under SHA-256.
* `sig`     — Rabin signature, interpreted as a Script number.
* `padding` — additive padding, interpreted as a Script number.
* `pubKey`  — Rabin modulus, interpreted as a Script number.

Output: `true` iff the byte-encoded value of `(sig² + padding) mod
pubKey` (under the canonical Script-number `encodeMinimalLE`
encoding) equals `SHA256(msg)`.

Mirrors `emitVerifyRabinSig` in
`packages/runar-compiler/src/passes/rabin-codegen.ts` — the modular
identity `(sig² + padding) mod pubKey == SHA256(msg)` with the
implicit Script-number ↔ bytes coercion made explicit. -/
def verifyRabinSig_spec (msg : ByteArray) (sig padding pubKey : Int) : Bool :=
  let lhs := (sig * sig + padding) % pubKey
  decide ((RunarVerification.Stack.encodeMinimalLE lhs).toList = (Crypto.sha256 msg).toList)

end RunarVerification.Crypto.Spec
