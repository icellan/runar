# Gate 0 Re-evaluation: STARK vs Groth16 On-chain Verification

## Overview

This document evaluates and compares two verification paths for on-chain BSVM proof
verification in the Runar compiler:

1. **STARK path (StackedBasefold)**: KoalaBear field arithmetic, Poseidon2 permutation,
   Poseidon2 Merkle trees, Fiat-Shamir sponge, Basefold verifier
2. **Groth16 path (BN254)**: BN254 Fp field arithmetic, G1 curve operations,
   Fp2/Fp6/Fp12 extension tower, optimal Ate pairing, Groth16 verifier

All measurements are taken from the Go codegen implementation in
`compilers/go/codegen/`, using actual StackOp counts produced by the emit functions.
Byte estimates use the Bitcoin Script encoding rules: single-byte opcodes, 1-byte
length prefix for pushdata up to 75 bytes, OP_PUSHDATA1 for larger values.

---

## 1. Script Size Measurement

### 1.1 STARK Path Components

Source files: `koalabear.go`, `poseidon2_koalabear.go`, `poseidon2_merkle.go`,
`fiat_shamir_kb.go`

#### KoalaBear Field Arithmetic (p = 2^31 - 2^24 + 1 = 2,130,706,433)

All values fit in a single BSV script number (31-bit prime). No multi-limb arithmetic.

| Operation   | StackOps | Bytes | Notes |
|-------------|----------|-------|-------|
| FieldAdd    |        5 |     9 | (a + b) mod p |
| FieldSub    |        9 |    21 | (a - b + p) mod p |
| FieldMul    |        5 |     9 | (a * b) mod p |
| FieldInv    |      357 |   593 | a^(p-2) via Fermat, 30 squarings + 29 muls |

#### KoalaBear Ext4 Arithmetic (F_p^4 over x^4 - 3)

| Operation      | StackOps | Bytes | Notes |
|----------------|----------|-------|-------|
| Ext4Mul (r0)   |       77 |  ~140 | 4 Fp muls + 3 Fp adds + 1 mulConst per component |
| Ext4Mul (r1)   |       77 |  ~140 | |
| Ext4Mul (r2)   |       77 |  ~140 | |
| Ext4Mul (r3)   |       72 |  ~130 | Slightly fewer (no mulConst) |
| Ext4Inv (r0)   |      550 |  ~950 | Includes 1 Fp inverse (~357 ops) |
| Ext4Inv (r1)   |      559 |  ~960 | |
| Ext4Inv (r2)   |      545 |  ~940 | |
| Ext4Inv (r3)   |      554 |  ~950 | |

#### Poseidon2 KoalaBear Permutation

Parameters: width=16, external rounds=8, internal rounds=20, S-box=x^3.

| Operation          | StackOps | Bytes    | Notes |
|--------------------|----------|----------|-------|
| Permute (full 16)  |   14,888 |  24,676  | 28 rounds, all 16 elements |
| Compress (trunc 8) |   14,892 |  24,680  | Permute + drop 8 elements + reorder |

The compress function is marginally larger than the raw permute due to additional
drop and reorder operations for the non-digest portion.

#### Poseidon2 Merkle Verification

Each level of the Merkle tree requires one Poseidon2 compress plus conditional swap
logic and stack reordering for siblings.

| Depth | StackOps  | Bytes      | Per Level |
|-------|-----------|------------|-----------|
|     1 |    14,904 |     24,709 |  ~14,904  |
|     5 |    74,812 |    123,974 |  ~14,962  |
|    10 |   150,057 |    248,612 |  ~15,006  |
|    20 |   301,747 |    500,337 |  ~15,087  |
|    25 |   378,192 |    627,744 |  ~15,128  |
|    30 |   455,037 |    755,954 |  ~15,168  |

Per-level cost increases slightly with depth due to deeper roll operations
for moving elements past future siblings.

#### Fiat-Shamir Sponge (DuplexChallenger)

Based on test output (`fiat_shamir_kb_test.go`):

| Operation              | StackOps | Notes |
|------------------------|----------|-------|
| Init (16 zeros)        |       16 | Push 16 zero field elements |
| Observe (no permute)   |        3 | Stack manipulation only |
| Observe (triggers perm)|   14,924 | Permute fires on 8th absorption |
| Squeeze (after partial)|   14,919 | Pad + permute + read rate[0] |
| SqueezeExt4            |   44,768 | 4 squeezes, each may trigger permute |
| SampleBits(8)          |        4 | Squeeze + OP_MOD mask |
| CheckWitness(16)       |   14,928 | Observe + squeeze + assert |

### 1.2 Groth16 Path Components

Source files: `bn254.go`, `bn254_ext.go`, `bn254_pairing.go`

#### BN254 Fp Field Arithmetic (p = 254-bit prime)

All operations use multi-byte bigint pushes (each p constant is 32 bytes + sign byte
= 34 bytes encoded). Fermat inverse iterates over 253 bits of p-2, with popcount 110.

| Operation   | StackOps | Bytes   | Notes |
|-------------|----------|---------|-------|
| FpAdd       |       12 |      44 | (a + b) mod p, double-mod pattern |
| FpSub       |       12 |      44 | (a - b + p) mod p |
| FpMul       |       12 |      44 | (a * b) mod p |
| FpInv       |    4,709 |  16,293 | a^(p-2), 253 squarings + 109 multiplications |
| FpNeg       |       24 |     ~88 | (p - a) mod p |

Each Fp operation pushes the 254-bit prime p as a constant (34 bytes), making
even simple adds cost 44 bytes.

#### BN254 G1 Curve Operations

| Operation    | StackOps | Bytes    | Notes |
|--------------|----------|----------|-------|
| G1 Add       |    6,245 |   18,127 | Affine addition (1 inv + muls) |
| G1 ScalarMul |   63,088 |  414,957 | Jacobian double-and-add, 254-bit loop |
| G1 Negate    |      ~24 |     ~100 | y-coordinate negation |
| G1 OnCurve   |     ~100 |     ~400 | y^2 == x^3 + 3 check |

G1ScalarMul dominates: 254 Jacobian doublings + ~127 mixed additions + final
Jacobian-to-affine conversion (1 inverse + 2 muls).

#### BN254 Full Pairing (Miller Loop + Final Exponentiation)

| Operation          | StackOps    | Bytes       | Size     |
|--------------------|-------------|-------------|----------|
| BN254 Pairing      |  2,444,695  |  6,672,447  | 6.4 MB   |

Breakdown by phase (estimated from code structure):

**Miller loop** (64 iterations over NAF of |6x+2|, 66 NAF digits):
- 64 Fp12 squarings
- 64 line evaluations (doubling) producing Fp12 elements
- 64 Fp12 multiplications (f *= line)
- 22 line evaluations (addition, for non-zero NAF digits)
- 22 Fp12 multiplications (f *= line)
- 2 Frobenius corrections (Q1, Q2) with line evaluations
- Each Fp12 multiply involves 3 Fp6 multiplies, each Fp6 multiply involves
  6 Fp2 multiplies, each Fp2 multiply involves 4 Fp multiplies.
- Estimated: ~1.8-2.0M ops for the Miller loop alone

**Final exponentiation** ((p^12 - 1)/r):
- Easy part: 1 Fp12 conjugate + 1 Fp12 inverse + 1 Fp12 multiply +
  1 Frobenius(p^2) + 1 Fp12 multiply
- Hard part: 3 Fp12 exponentiation by x (63-bit, ~62 squarings + ~31 muls each)
  + multiple Frobenius maps + ~6 Fp12 multiplies
- Estimated: ~0.4-0.6M ops for the final exponentiation

---

## 2. Estimated Total Script Sizes

### 2.1 STARK (StackedBasefold) Verifier

SP1 v6 StackedBasefold uses 124 FRI queries, each requiring Merkle path verification.
The Merkle tree depth depends on the trace length. For a representative program:

**Assumptions:**
- Trace length: 2^20 to 2^25 (Merkle depth 20-25)
- FRI queries: 124
- Sumcheck rounds: ~21 (log2 of trace length for degree-2)
- Each sumcheck round: ~4 Ext4 multiplications + 2 Ext4 additions + 1 squeeze

| Component | Count | Ops/Unit | Total Ops | Total Bytes |
|-----------|-------|----------|-----------|-------------|
| Merkle path verify (depth 25) | 124 | 378,192 | 46,895,808 | 77,840,256 |
| Poseidon2 compress (FRI folding) | ~2,600 | 14,892 | 38,719,200 | 64,168,000 |
| Fiat-Shamir squeezes | ~200 | 14,919 | 2,983,800 | 4,953,360 |
| Ext4 multiplications (sumcheck) | ~100 | 303 | 30,300 | 55,000 |
| Ext4 inversions | ~20 | 2,208 | 44,160 | 76,000 |
| Fiat-Shamir init + observations | ~500 | ~50 avg | 25,000 | 40,000 |
| **Total estimate** | | | **~88,700,000** | **~147 MB** |

**Key insight:** The STARK verifier is dominated by Poseidon2 Merkle verification.
Each of the 124 queries requires a full Merkle path (depth 25 = 25 Poseidon2 compress
operations). Additionally, FRI requires checking evaluations at multiple layers,
each needing additional Poseidon2 compressions for commitment verification.

The 147 MB estimate far exceeds BSV's 10 MB default script size limit and likely
exceeds any reasonable miner-configured maximum.

### 2.2 Groth16 (BN254) Verifier

The Groth16 verifier requires:
1. Input preparation: 1 G1 scalar multiplication + 1 G1 point addition (per public input)
2. 4 pairings: e(-A, B), e(prep, gamma), e(C, delta), e(alpha, -beta)
3. 3 Fp12 multiplications (combine pairing results)
4. 1 Fp12 identity check

**Optimization: multi-pairing with shared final exponentiation.**
Instead of 4 separate pairings, run 4 Miller loops and multiply the results
before a single final exponentiation:

| Component | Count | Ops/Unit | Total Ops | Total Bytes |
|-----------|-------|----------|-----------|-------------|
| G1 ScalarMul (input prep) | 1 | 63,088 | 63,088 | 414,957 |
| G1 Add (input prep) | 1 | 6,245 | 6,245 | 18,127 |
| G1 Negate | 2 | ~24 | ~48 | ~200 |
| G1 OnCurve checks | 3 | ~100 | ~300 | ~1,200 |
| Miller loop (shared) | 4 | ~1,800,000 | ~7,200,000 | ~19,600,000 |
| Fp12 Mul (combine 4 results) | 3 | ~40,000 | ~120,000 | ~330,000 |
| Final exponentiation (1x) | 1 | ~500,000 | ~500,000 | ~1,400,000 |
| **Total estimate** | | | **~7,890,000** | **~21.4 MB** |

**Note:** The actual measured single-pairing cost is 2,444,695 ops / 6,672,447 bytes
(6.4 MB). With shared final exponentiation, 4 pairings cost approximately:
- 4 Miller loops: ~4 * 5.0 MB = ~20.0 MB (Miller is ~75-80% of pairing cost)
- 1 final exp: ~1.4 MB
- Input prep + combines: ~0.8 MB
- **Realistic total: ~22.2 MB**

This also exceeds the 10 MB default but is within reach with miner configuration
(BSV miners can raise the limit). However, additional optimization is possible:

**Sparse Fp12 multiplication optimization:** Line evaluation results are sparse
(only 6 of 12 Fp components are non-zero). Using sparse-by-dense Fp12
multiplication could reduce the Miller loop cost by ~40%, bringing the total
down to approximately:
- 4 sparse Miller loops: ~12.0 MB
- 1 final exp: ~1.4 MB
- Other: ~0.8 MB
- **Optimized total: ~14.2 MB**

---

## 3. Comparison Table

| Metric | STARK (StackedBasefold) | Groth16 (BN254) |
|--------|------------------------|-----------------|
| **Proof size** | ~1,243 KB | ~256 bytes |
| **Verifier script size** | ~147 MB (est.) | ~22 MB (est.) / ~14 MB (optimized) |
| **StackOps count** | ~88,700,000 | ~7,890,000 |
| **Dominant cost** | 124 * Poseidon2 Merkle | 4 * Miller loop |
| **Field element size** | 31 bits (single word) | 254 bits (34-byte pushes) |
| **Ops per field mul** | 5 | 12 |
| **Bytes per field mul** | 9 | 44 |
| **Field inverse cost** | 357 ops / 593 B | 4,709 ops / 16,293 B |
| **Hash function** | Poseidon2 (14,888 ops) | N/A (SHA-256 for input only) |
| **Peak stack depth** | ~40 (Merkle + sponge) | ~60-80 (Fp12 tower operations) |
| **Practical for BSV?** | No (15x over limit) | Marginal (1.4-2.2x over limit) |

---

## 4. Trade-off Analysis

### 4.1 Proof Size vs Verifier Size

The fundamental trade-off between STARK and Groth16 is reversed from their off-chain
characteristics when considering on-chain verification:

- **STARK proofs are large (~1.2 MB)** but are typically considered to have
  "efficient" verification. However, "efficient" in the STARK context means
  polylogarithmic in the trace length -- and the constants are enormous. With 124
  FRI queries, each requiring a full Poseidon2 Merkle path, the verifier script
  is approximately 147 MB.

- **Groth16 proofs are tiny (~256 bytes)** with constant-time verification (always
  4 pairings regardless of circuit size). The verifier script is ~22 MB
  (naive) or ~14 MB (with sparse multiplication optimization).

### 4.2 Why STARK Verification Is So Expensive

The StackedBasefold verifier's cost is dominated by hash evaluations:

1. **124 FRI queries**: Each query verifies a Merkle path of depth ~25, requiring
   25 Poseidon2 compress operations (25 * 14,892 = 372,300 ops per query).
   Total: 124 * 372,300 = **46.2M ops** just for Merkle verification.

2. **FRI folding**: Each query also requires evaluating the FRI polynomial at
   multiple layers, with additional Poseidon2 hash evaluations for commitment
   verification.

3. **Poseidon2 dominates**: A single Poseidon2 compress costs 14,892 StackOps
   (24.1 KB). The verifier needs approximately 3,000-6,000 Poseidon2 invocations.

Even though KoalaBear field arithmetic is extremely cheap (5 ops for a multiply,
vs 12 for BN254), the sheer number of hash evaluations makes the STARK verifier
10x larger than the Groth16 verifier.

### 4.3 Why Groth16 Is More Feasible

Despite BN254 arithmetic being expensive per operation (254-bit numbers, 34 bytes
per prime push), the Groth16 verifier has **constant-size** independent of the
circuit. The dominant cost is 4 pairings, each requiring ~64 Fp12 operations
in the Miller loop. Key factors:

1. **Fixed iteration count**: The Miller loop iterates exactly 64 times (NAF length
   of |6x+2| = 66 digits, 43 zeros, 11 ones, 12 negative ones).

2. **Sparse optimization potential**: Line evaluation results have only 6 non-zero
   Fp components out of 12. Exploiting this sparsity reduces Fp12 multiplication
   cost by ~40%.

3. **Shared final exponentiation**: The most expensive single operation (Fp12 exp
   by (p^12-1)/r) is performed only once, regardless of the number of pairings.

### 4.4 BSV Script Size Limits

- **Default BSV limit**: 10 MB (miners can configure higher)
- **Groth16 (optimized)**: ~14 MB -- 1.4x the default limit. Achievable with
  modest miner configuration changes. Further optimizations (precomputed tables,
  cyclotomic squaring) could potentially bring this under 10 MB.
- **STARK (Basefold)**: ~147 MB -- 15x the default limit. Impractical even with
  aggressive miner configuration.

### 4.5 Recommendation

**Groth16 is the more practical path for on-chain verification.** While still
exceeding the default script size limit, it is within a realistic range for BSV
deployment with miner cooperation. The STARK path would require either:

- Reducing the number of FRI queries (weakening security)
- Splitting verification across multiple transactions (adding protocol complexity)
- A fundamentally different hash function with lower script cost

For ZK proof verification on BSV, the recommended approach is:
1. Use SP1 to generate proofs of arbitrary computation
2. Wrap the proof in Groth16 (SP1 supports this natively)
3. Verify the Groth16 proof on-chain using the BN254 pairing codegen

---

## 5. Implementation Status

### 5.1 STARK Path Modules

| Module | File | Status | Notes |
|--------|------|--------|-------|
| KoalaBear field (Fp) | `koalabear.go` | Complete | Add, sub, mul, inv, ext4 mul/inv |
| Poseidon2 permutation | `poseidon2_koalabear.go` | Complete | 28 rounds, SP1 v6.0.2 constants |
| Poseidon2 Merkle | `poseidon2_merkle.go` | Complete | Arbitrary depth, conditional swap |
| Fiat-Shamir sponge | `fiat_shamir_kb.go` | Complete | Init, observe, squeeze, ext4, checkWitness |
| Basefold verifier | -- | Not started | No codegen module exists yet |
| FRI verifier | -- | Not started | Requires Basefold verifier |
| Sumcheck verifier | -- | Not started | Requires ext4 arithmetic (available) |

All STARK building blocks (field arithmetic, hash function, Merkle proofs,
Fiat-Shamir) are complete and tested. The missing piece is the orchestrating
Basefold verifier that combines them into the full verification protocol.

### 5.2 Groth16 Path Modules

| Module | File | Status | Notes |
|--------|------|--------|-------|
| BN254 Fp field | `bn254.go` | Complete | Add, sub, mul, inv, neg; 254-bit Fermat inverse |
| BN254 G1 operations | `bn254.go` | Complete | Add (affine), ScalarMul (Jacobian), Negate, OnCurve |
| Fp2 extension | `bn254_ext.go` | Complete | Add, sub, mul, sqr, inv, conjugate, mulByNonResidue |
| Fp6 extension | `bn254_ext.go` | Complete | Add, sub, mul, neg, inv, mulByNonResidue |
| Fp12 extension | `bn254_ext.go` | Complete | Add, sub, mul, sqr, inv, conjugate, expByX |
| Fp12 Frobenius | `bn254_ext.go` | Complete | FrobeniusP, FrobeniusP2 (TODO: verify constants) |
| Miller loop | `bn254_pairing.go` | Complete | Optimal Ate, NAF of |6x+2|, G2 Frobenius corrections |
| Final exponentiation | `bn254_pairing.go` | Complete | Easy part + hard part (Devegili decomposition) |
| Full pairing | `bn254_pairing.go` | Complete | EmitBN254Pairing entry point (2,444,695 ops) |
| Groth16 verifier contract | `integration/go/contracts/` | Structural | Frontend compiles; codegen builtins TODO |
| Sparse Fp12 multiply | -- | Not started | Key optimization for Miller loop |

The full pairing codegen is complete and emits 2.44M StackOps (6.4 MB per pairing).
The Groth16 verifier contract exists but uses secp256k1 EC builtins as placeholders;
it needs bn254-specific builtins wired through the compiler pipeline (typecheck,
ANF lowering, stack lowering).

**Bug fixed during this evaluation:** `bn254G2Negate` used incorrect name suffixes
(`_x0` instead of `_x_0`) and the Miller loop used `bn254Fp12RenamePrefix` for
a G2 point instead of `bn254RenameG2`. Both bugs prevented `EmitBN254Pairing`
from running to completion.

### 5.3 Remaining Work for Groth16 Deployment

1. **Wire BN254 builtins through compiler pipeline**: Add `bn254G1Add`,
   `bn254G1ScalarMul`, `bn254G1Negate`, `bn254Pairing`, `bn254Fp12Mul`,
   `bn254Fp12IsOne` as recognized builtins in typecheck, ANF lowering, and
   stack lowering for all 6 compilers.

2. **Implement sparse Fp12 multiplication**: Line evaluations produce sparse
   Fp12 elements. A dedicated sparse-by-dense Fp12 multiply would reduce the
   Miller loop cost by ~40%.

3. **Multi-pairing optimization**: Share the final exponentiation across all 4
   pairings. Run 4 Miller loops, multiply results, then do one final exp.

4. **Verify Frobenius constants**: The Fp12 Frobenius maps use precomputed
   constants that should be verified against a reference implementation
   (gnark-crypto, py_ecc).

5. **End-to-end test**: Compile a Groth16 verifier contract to Bitcoin Script,
   execute against a real SP1 Groth16 proof on regtest.

6. **Proof-point curve and subgroup checks (SECURITY)**: The current
   `EmitGroth16VerifierWitnessAssisted` performs an on-curve check only on
   the prover-supplied `prepared_inputs` (G1). `proof.A` (G1), `proof.B`
   (G2), and `proof.C` (G1) are accepted without curve or subgroup
   validation. The witness-assisted gradient checks enforce that the
   supplied `lambda` is consistent with the claimed coordinates but do NOT
   force the coordinates to lie on the BN254 curve (G1) or twist curve (G2),
   and do not enforce prime-order subgroup membership.

   A malicious prover could in principle forge the pairing identity by
   supplying a G2 point with a small-order component (small-subgroup attack;
   see Barreto et al., "Subgroup security in pairing-based cryptography").
   The current design is sound when the prover is honest (e.g. SP1's
   gnark-backed Groth16 wrapper always emits valid points); it is NOT sound
   against a hostile prover that bypasses the Rúnar SDK and crafts witness
   values by hand.

   Required mitigations before production deployment:
   - Add `emitWAG1OnCurveCheck` calls for `proof.A` and `proof.C` (~40
     StackOps each, ~80 bytes total).
   - Add `emitWAG2OnCurveCheck` for `proof.B` verifying
     `y² == x³ + 3/(9+u)` in Fp2 (~100 StackOps). Requires computing the
     BN254 twist constant `b' = 3/(9+u) mod p` and baking it as an Fp2
     literal.
   - Add G2 subgroup check for `proof.B` — either `r·B == O` (expensive,
     one full G2 scalar multiplication by the BN254 group order r ~ 254
     bits) or the BN-specific trace-based check `(p+1-t)·B == 0` which is
     cheaper because `(p+1-t)` has lower Hamming weight. Estimated cost:
     20-40 KB of additional script. The choice of check and its
     correctness must be validated against gnark-crypto test vectors.

   Until item 6 is implemented, the regtest spend test
   `TestGroth16WA_Regtest_TamperedProofA_Rejected` only demonstrates
   rejection of a proof-A tamper via the final pairing check; it does NOT
   demonstrate subgroup-security. A targeted test using a crafted
   small-order G2 point should be added alongside the check.

---

## Appendix A: Measurement Methodology

All StackOp counts were obtained by calling the Go codegen `Emit*` functions
and counting the emitted `StackOp` structs. Byte estimates were computed by
mapping each StackOp to its Bitcoin Script encoding:

- Simple opcodes (OP_ADD, OP_MUL, OP_DUP, etc.): 1 byte
- Push of bigint value: 1 byte (OP_0, OP_1..OP_16) or 1+N bytes (length prefix + data)
- Push of BN254 field prime (254-bit): 34 bytes (1 length + 32 data + 1 sign)
- Push of KoalaBear prime (31-bit): 5 bytes (1 length + 4 data)
- OP_IF/OP_ELSE/OP_ENDIF: 1 byte each
- ROLL/PICK: preceded by a separate push of the depth value

The programs used for measurement are standalone Go programs that import
`codegen` and call the public `Emit*` functions.

## Appendix B: NAF of |6x+2| for BN254 Miller Loop

|6x+2| = 29,793,968,202,426,331,778

NAF representation (66 digits, LSB first):
- 43 zeros, 11 ones, 12 negative ones
- MSB index: 65
- Miller loop iterations: 64 (MSB-1 down to 0)
- Doublings per iteration: 1 (total 64)
- Additions per iteration: varies (total 22 for non-zero NAF digits)

## Appendix C: BN254 Field Inverse Cost Breakdown

p-2 has 254 bits with popcount 110.
- Squarings: 253 (bits 252 down to 0)
- Conditional multiplications: 109 (for each set bit except MSB)
- Each squaring: 1 FpSqr (= 1 copy + 1 FpMul) = ~14 ops
- Each multiplication: 1 copy + 1 FpMul = ~14 ops
- Total: 253*14 + 109*14 = 5,068 ops (measured: 4,709 ops due to optimizations)
