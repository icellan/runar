# EC degenerate cases — semantics and the commit-pairing constraint (2026-08)

Durable record for the three degenerate inputs the secp256k1 / P-256 / P-384
codegen has to answer for, and for a **bisect hazard** that is invisible in any
single commit.

## ⚠ `03f50d48` and `f16790a9` MUST NEVER BE SEPARATED

`03f50d48` gave the scalar ladder an add-or-double select at its **last step
only**. The proof that one step suffices is an interval argument: after step `i`
the accumulator holds `c_i·P` with `c_i = (k + 3n) >> i`, and the degenerate
cases are `c_i ≡ 0, 1, 2 (mod n)`. Enumerating them by interval arithmetic
shows only `i = 0` qualifies.

**That enumeration is conditioned on `k ∈ [0, n−1]`.** The reduce that makes it
true — `k mod n` before the `+3n` — landed in the NEXT commit, `f16790a9`.

So `03f50d48` on its own is **unsound**: with an unbounded scalar, `c_i` is free
to hit `0, 1, 2 (mod n)` at steps other than `i = 0`, where there is no select
and the Jacobian mixed-add silently returns the point at infinity (`Z3 = 0`,
which `fieldInv`-as-Fermat turns into the all-zero point). The scalar is
normally an unlock argument, i.e. attacker-chosen.

Consequences:

- never `git bisect` a range that lands between these two commits and trust the
  result of an EC test;
- never cherry-pick or revert one without the other;
- any change to the `+3n` offset, the iteration count, or the reduce invalidates
  the interval argument and must redo it.

This warning is duplicated in the `buildJacobianAddOrDoubleInline` comment of
all seven tiers' EC codegen modules, because that is where someone will be
standing when they consider changing it.

## The three degenerate inputs and their answers

The affine `x‖y` encoding cannot represent the point at infinity `O`. Rather
than fail, the codegen encodes `O` as the **all-zero blob** and relies on
`ecOnCurve` / `pNNNOnCurve` to reject it (`0² ≠ 0³ + b` on all three curves).

| Input | Result | Where |
|---|---|---|
| `ecMul(P, 0n)`, `ecMulGen(0n)`, any `k ≡ 0 (mod n)` | all-zero point | ladder: `Z3 = 0` |
| `ecAdd(P, ecNegate(P))`, any `P.x == Q.x` with `P.y != Q.y` | all-zero point | `affineAdd` `notinf` mask |
| `ecAdd(P, P)` | `2P` (tangent) | `affineAdd` `cond` select |

The second row is the 2026-08 change. Selecting the tangent on `px == qx`
**alone** — as `03f50d48` did — answered `P + (−P)` with `2P`: on-curve,
plausible, and wrong. That is strictly worse than the behaviour it replaced,
because the pre-`03f50d48` chord path divided by zero and produced an *off*-curve
blob, so the idiom the codegen documents —

```ts
const r = p384Add(a, b);
assert(p384OnCurve(r));
```

— used to reject `p384Add(G, p384Negate(G))` and, after `03f50d48`, accepted it.

### Why all-zero and not "reject"

Three reasons, in order of weight:

1. **The optimizer already answers all-zero.** `ec-mulgen-linear` in
   `optimizer/ec-rules.json` rewrites `ecAdd(ecMulGen(k1), ecMulGen(k2))` into
   `ecMulGen(k1 + k2)`. For `k1 + k2 ≡ 0 (mod n)` the rewritten spelling is
   `ecMulGen(0)` → all-zero. Rejecting in `ecAdd` would make the same source
   produce two different behaviours depending on whether the optimizer fired.
2. It matches `ecMul(P, 0n)`, so `O` has ONE encoding across the whole surface.
3. `ecAdd` is a pure value-producing expression with no failure channel; adding
   one turns attacker-chosen input into a liveness failure. Same argument
   `f16790a9` used for reducing the scalar instead of rejecting it.

Measured cost: **+21 script bytes** per `ecAdd` / `p256Add` / `p384Add`
(+0.083% / +0.106% / +0.045%).

## `decompressPubKey` and the ladder's precondition

The ladder's exception analysis holds for points **on** the curve, where
cofactor 1 pins `ord(P) = n`. `decompressPubKey` (the P-256 / P-384 ECDSA
verifier's only pubkey entry point) computed `y = (x³ − 3x + b)^((p+1)/4)` and
never checked `y² == x³ − 3x + b`, nor `x < p`. For an `x` whose RHS is a
quadratic non-residue the recovered point is off-curve — it lies on the twist,
whose order is composite — and went straight into `cEmitMul`.

It now emits `valid = (x < p) AND (y² == x³ − 3x + b)`, ANDed into the verifier's
boolean result. A flag rather than an `OP_VERIFY`, for reason 3 above.

**Severity of the decompression guard specifically:** defence in depth. Making
`(R.x mod n) == r` succeed with an attacker-chosen off-curve `Q` is equivalent
to forging ECDSA, so that guard's regression test is a pin rather than a
red-then-green proof.

> ### ⚠ CORRECTION (2026-08-06): the claim that used to stand here was FALSE
>
> This section previously said, of the whole verifier: *"Every input that trips
> the guard also fails the final `(R.x mod n) == r` comparison … No pre-fix
> `true` is constructible."* The first clause is true of the **decompression**
> guard. Generalising it to the verifier was wrong, and it hid the most severe
> defect in this audit series. A `true` **was** constructible, it needed no
> off-curve `Q`, and it was not equivalent to forging ECDSA. See the next
> section.

## The universal forgery: `r` and `s` were never range-checked

`verifyECDSA_P256` / `verifyECDSA_P384` split the signature into `r` and `s` and
never checked `r != 0`, `s != 0`, `r < n` or `s < n` (SEC1 §4.1.4 step 1 /
FIPS 186-5 §6.4.2). `cGroupInv` is Fermat — `a^(n-2) mod n` — so `inv(0) = 0`
rather than an error, and every degenerate value flows through instead of
failing.

Take `sig` = 64 zero bytes (96 for P-384) and the contract's own **genuine,
public** key:

| step | value | why |
|---|---|---|
| `_r`, `_s` | `0` | `BIN2NUM` of 32 zero bytes is the empty vector |
| `_w = s^(n-2)` | `0` | Fermat inverse of 0, no failure channel |
| `_u1`, `_u2` | `0` | every `cGroupMul` in the ladder is `0*0 mod n` |
| `R1 = u1*G` | all-zero point | scalar reduce gives 0, `k' = 3n ≡ 0 (mod n)`, so `Z3 = 0` and the Fermat inverse in `cJacobianToAffine` zeroes it |
| `R2 = u2*Q` | all-zero point | same |
| `R1 + R2` | `(0, 0)` | `cAffineAdd` sees `xeq = yeq = 1`, takes the TANGENT branch, `den = 2*0 = 0`, so `s = 0` and `rx = ry = 0` |
| `_rx_mod_n` | empty vector | `0 mod n` |
| `OP_EQUAL(_rx_mod_n, _r_save)` | **1** | `OP_EQUAL(<>, <>)` |
| `_dk_valid` | `1` | the pubkey is genuine |
| `OP_BOOLAND` | **TRUE** | |

No secret material, no off-curve point, and not bound to the message: an
all-zero signature verified for **any** message under **any** public key. That
is a universal forgery, not a hygiene issue.

`r = 0, s = n` is a second spelling of it — `n^(n-2) mod n` is also `0` — which
is why the fix bounds both values by `< n` rather than only testing `!= 0`.

**Live exposure in-tree.** `examples/ts/p256-wallet/P256Wallet.runar.ts:62` makes
`assert(verifyECDSA_P256(sig, p256Sig, p256PubKey))` the entire second factor of
a contract whose stated model is "an HSM or WebAuthn key gates Bitcoin
spending". An attacker holding only the secp256k1 key supplied 64 zero bytes as
`p256Sig` together with the genuine, public `p256PubKey`; `hash160(p256PubKey)`
matched the committed hash and the P-256 factor was bypassed entirely.

### Why nothing caught it

Two independent gaps, and each on its own was enough:

1. **The differential oracle disagreed and the disagreement was invisible.**
   `packages/runar-testing/src/interpreter/interpreter.ts` implements
   `verifyECDSA_*` with Node/OpenSSL, which rejects `(0, 0)`. So for the same
   source the interpreter answered `false` and the script answered `true` — the
   exact divergence a source-vs-script oracle exists to find. It was never run
   on this builtin.
2. **The only real-`Spend` test never varied the signature.**
   `packages/runar-testing/src/__tests__/p256-p384-ecdsa-verify.test.ts` had five
   cases, all varying the *pubkey encoding* or the message. The signature bytes
   came from OpenSSL every time and were never malformed.

### The fix

`cEmitSigRangeGate` emits, per value, `OP_0NOTEQUAL` and `OP_LESSTHAN n`, joined
with `OP_BOOLAND`, and the result is `OP_BOOLAND`ed into the verifier's boolean
alongside the decompression verdict. A flag, not an `OP_VERIFY`, for the same
reason the decompression guard is one.

Two more argument defects were fixed in the same pass, both also returning
`false` rather than aborting:

- **No length validation.** `sig` and `pubkey` are bare `ByteString` in
  `packages/runar-lang/src/builtins.ts` and `03-typecheck.ts` imposes no width.
  The verifier took *everything after* `coordBytes` as `s`, so `sig ‖ junk`
  verified identically to `sig` — fatal for any contract using signature bytes
  as a nullifier. And for `coordBytes <= len(sig) < 2*coordBytes` the byte
  reversal's `OP_SPLIT 1` ran off the end and **aborted the script**, which
  would make `verifyECDSA_P256(...) || fallback` unwritable. `cEmitLengthGate`
  now clamps each argument to its exact width (branch-free: `v ‖ 00*want`, split,
  drop) and `OP_BOOLAND`s the size verdict into the result.
- **Compressed prefix not validated.** The parity reduction was
  `OP_BIN2NUM, 2 OP_MOD`, so `0x00` / `0x04` / `0x82` all aliased to "even" —
  and `0x83` was worse than an alias: `BIN2NUM(0x83) = -3`, `-3 mod 2 = -1`,
  which encodes as `0x81` and never equals `_dk_y_par ∈ {<>, 0x01}`, so the
  select silently returned the *other* square root. Whether that verified
  depended on the key's parity — for one of the two OpenSSL fixtures in the test
  it did. The prefix byte is now tested against `0x02` / `0x03` directly.

**Not fixed, deliberately: low-S.** `(r, s)` and `(r, n - s)` both verify.
Enforcing low-S would reject conforming FIPS 186-5 signatures from OpenSSL and
from WebAuthn authenticators, turning an interop detail into an unspendable
output — the same liveness argument that makes every guard here a flag rather
than an abort. It is documented in `docs/language-reference.md` instead, with
the instruction to derive any uniqueness key from the message or from `r`, not
from the signature blob.

Measured cost: **+225 bytes** on `verifyECDSA_P256` (0.023%) and **+306 bytes**
on `verifyECDSA_P384` (0.015%); +58 emitted ops on both, the count being
curve-independent because none of the gates loops.

Red-then-green, through the real `@bsv/sdk` `Spend`, in
`packages/runar-testing/src/__tests__/p256-p384-ecdsa-verify.test.ts`: the
all-zero signature returned `true` on both curves before the change and `false`
after, and the OpenSSL accept case still passes. That file's `verify()` helper
now also asserts on **every** call that the script neither aborted nor left more
than one item, which is what pins totality.

## BN254 G1: the same defect class, re-derived rather than assumed

`bn254G1ScalarMul` and the Groth16 `emitG1ScalarMulNamed` are the same
`k + 3r`, MSB-first, Jacobian mixed-add ladder. The interval argument was redone
for BN254 rather than carried over, and **the secp256k1 numbers do not apply**:

| | secp256k1 | BN254 |
|---|---|---|
| order bit length | 256 | **254** |
| offset | `3n`, 258 bits | `3r`, **256 bits** |
| accumulator seeded at bit | 257 | **255** |
| iterations | 257 | **255** |

`3r >= 2^255` and `4r - 1 < 2^256`, so for `k ∈ [0, r-1]` bit 255 is always set
and nothing above it ever is. The existing offset and iteration count were
therefore already right — but the precondition they rest on was not enforced:

- **No `k mod r` reduce.** `k >= 2^256 - 3r` (≈ `2.2902 r`) sets bit 256, which
  the loop never reads; `k <= -r` drops `k'` below `2^255`, making the seeded
  accumulator bit a lie. Either way the ladder returns a **different multiple of
  P** rather than failing. In Groth16 the scalars are the caller-supplied public
  inputs of `vk_x = IC[0] + Σ IC[i]·pub_i`.
- **The exceptional-case test was `H == 0` alone.** Sweeping `c_i = k' >> i`
  over `k ∈ [0, r-1]` puts the mixed-add's degenerate cases at `i = 0` only, at
  `k = 2` (accumulator `= +P`) and `k = 0` (accumulator `= -P`). `k = 2` was
  already handled. `k = 0` was not: `H == 0` with `R != 0` also took the
  doubling branch and returned `-2P` where the answer is the point at infinity.
  A Groth16 public input of `0` is entirely ordinary. The test is now
  `H == 0 AND R == 0`, paid only at `i = 0` because the sweep proves the branch
  cannot fire anywhere else.

A previous comment in `bn254BuildJacobianAddAffineInline` asserted the
`acc = -base` case was "cryptographically unreachable for valid Groth16 public
inputs". It is reachable at `k = 0`; the comment has been corrected.

Measured cost on `bn254G1ScalarMul`: **134,181 → 134,245 bytes (+64, +0.048%)**,
decomposing as +41 for the reduce and +23 for the strict test at `i = 0`.
Applying the strict test at all 255 steps instead would have cost +5,865 bytes,
which is what the `i = 0` localisation buys. `bn254G1Add` was unchanged by that
pass (see the R-035 note below). No
conformance fixture exercises BN254, so no golden moved; the gate is
`compilers/go/codegen/bn254_scalar_domain_test.go`, which runs eight scalars
through the go-sdk interpreter and failed six of them before the fix.

### What was NOT changed in BN254 at the time, and what changed later

`bn254G1AffineAdd` uses the unified slope `s = (px² + px·qx + qx²) / (py + qy)`,
which is already correct for doubling — it never had the `ecAdd` bug. Its
`py + qy == 0` case produces an off-curve blob via `inv(0) = 0`, and masking
**a zero denominator** to the all-zero point would have been a regression:
BN254 has j-invariant 0 and `p ≡ 1 (mod 3)`, so `F_p` contains a primitive cube
root of unity `ω`; for any curve point `(x, y)` the point `(ωx, y)` is also on
the curve, so `Q = (ωx, -y)` gives `py + qy == 0` while `Q != -P` — and the true
sum `P + Q` is an **ordinary point**, not `O`. That would answer "point at
infinity" for those inputs: plausible and wrong, precisely the failure mode
`03f50d48` introduced on the NIST curves and `f16790a9` had to undo.

**Superseded for `P == -Q` (R-035).** The conclusion above was drawn about the
denominator test, and it was over-applied to the case the sibling curves
actually mask. secp256k1 and both NIST curves key their mask on the PRECISE
predicate `px == qx AND py != qy`, which on this curve holds only when
`Q == -P` (`py² = qy² = px³ + 3`), and never for `(ωpx, -py)` because
`ωpx != px`. `bn254G1Add` is a general contract-callable builtin with no
Groth16-shaped restriction on its operands, so it now returns the all-zero `O`
blob for `P + (-P)`, exactly like the other three families. The mask lives in
the builtin entry point (`bn254G1InfinityFlag` / `bn254G1MaskInfinity`), NOT in
`bn254G1AffineAdd`, so the Groth16 MSM bind that shares that helper keeps its
fail-closed behaviour and its bytes unchanged. Cost: **+25 bytes** on the
`bn254G1Add` builtin (4,482 → 4,507 standalone; 4,271 → 4,294 in the
`bn254G1OnCurve(bn254G1Add(a, b))` probe contract), byte-identical across all
six tiers that ship BN254 codegen. No conformance fixture exercises BN254, so
no golden moved. Pinned by `TestBN254G1Add_PointAtInfinity` (executed through
the go-sdk interpreter: `G + (-G)`, `(-G) + G`, `2G + (-2G)`, plus `G + 2G` and
`G + G` controls).

**Still open: the zero-denominator answer is WRONG, not fail-closed.** The
paragraph above claimed `(ωpx, -py)` fails closed. It does not. Both the
numerator and the denominator vanish (`ω² + ω + 1 = 0` makes
`px² + px·qx + qx² = 0`), so `s = 0`, and the result `(-(px + qx), -py)`
satisfies `y² = x³ + 3` because `(1 + ω)³ = -1`: `bn254G1Add` answers with a
plausible, on-curve, **wrong** point that `assert(bn254G1OnCurve(r))` does not
reject. Verified against the go-sdk interpreter. Fixing it means replacing the
unified slope with the chord/tangent selection secp256k1 and the NIST curves
use, which also moves the shared Groth16 MSM path — a separate change. The
current behaviour is pinned, and the mask's precision is guarded, by
`TestBN254G1AffineAdd_ZeroDenominatorIsNotMaskedToInfinity`.

## Found on the way in: five off-chain mocks disagreed with the script

Adding `assert(!ecOnCurve(ecAdd(g, neg)))` to the `ec-unit` fixture made the
Python example test fail — and the reason was not the compiler. Five of the
seven **off-chain runtime mocks** special-cased the all-zero blob as
"point at infinity, therefore on the curve":

| tier | before | after |
|---|---|---|
| TS (`runar-lang`) | `false` ✓ | unchanged |
| Go (`runar-go`) | `false` ✓ | unchanged |
| Rust (`runar-rs`) | `true` ✗ | `false` |
| Python (`runar-py`) | `true` ✗ | `false` |
| Zig (`runar-zig`) | `true` ✗ | `false` |
| Ruby (`runar-rb`) | `true` ✗ | `false` |
| Java (`runar-java`) | `true` ✗ | `false` |

Projectively `O` *is* on the curve, so the convention is defensible in the
abstract — but `ecOnCurve` is defined here by what the emitted script does, and
the script computes `x < p AND y < p AND y² == x³ + 7`, which is `false` for
`(0, 0)`. The mock therefore answered the opposite of the chain.

Direction of harm: a contract author writes the documented guard
`assert(ecOnCurve(r))`, it passes in unit tests against the mock when `r = O`,
and the deployed script rejects — an unspendable output discovered only after
funding. `O` is reachable from `ecMul(P, 0n)`, and, as of this change, from
`ecAdd(P, −P)` as well, so this stopped being theoretical.

The Zig and Rust suites each carried a test asserting the wrong answer
(`ecOnCurve(identity)` / `ec_on_curve_accepts_identity`); both were inverted
with a comment explaining why.

## Where these are gated

| Property | Test |
|---|---|
| `ecAdd(P, −P)` = all-zero, script AND interpreter, 3 curves | `packages/runar-testing/src/__tests__/ec-degenerate-add.test.ts` |
| scalar domain (`k ≥ n`, `k < 0`, `k ≡ 0`), 3 curves | `packages/runar-testing/src/__tests__/ec-scalar-domain.test.ts` |
| `ec-mulgen-linear` ↔ scalar reduce dependency | same file, `ec-mulgen-linear depends on the scalar reduce` |
| coordinate canonicity, x half AND y half, 3 curves | `packages/runar-testing/src/__tests__/ec-on-curve-canonicity.test.ts` |
| `verifyECDSA_P256/P384` accept + decompression guards | `packages/runar-testing/src/__tests__/p256-p384-ecdsa-verify.test.ts` |
| all seven tiers, real Spend engine | `conformance/witnesses/real-crypto/{ec-unit,p256-primitives,p384-primitives}.json` |

## Correction to an earlier claim

An earlier comment in `ec-on-curve-canonicity.test.ts` said the **y** half of the
canonicity guard had "no constructible witness", on the grounds that a curve
point with `y < 2^(8·w) − p` is a `2^-32` / `2^-224` / `2^-256` event. That is
only true of *random search*. Fix `y` and the curve equation is a cubic in `x`,
whose roots come out of `gcd(X^p − X, f)` over `F_p` in milliseconds. A small-`y`
witness now exists for **all three curves** and is computed in the test rather
than assumed away.
