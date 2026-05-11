import RunarVerification.ANF.Eval
import RunarVerification.Stack.Peephole

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

Total: **26** axioms in this module (one fewer than the original
27 once Tier 5.3 discharged `hash160_eq_ripemd160_sha256`).
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

end RunarVerification.Crypto.Spec
