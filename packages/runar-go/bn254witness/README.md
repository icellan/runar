# bn254witness

Off-chain witness generator for the Rúnar witness-assisted BN254 Groth16
verifier. This is the Go-side companion to the on-chain verifier emitted
by `compilers/go/codegen.EmitGroth16VerifierWitnessAssisted`: it takes a
verifying key, a proof, and a list of public input scalars, and produces
the exact stack initialization sequence the emitted script expects.

## Purpose

Groth16 verification on BN254 is dominated by two costly operations —
field inversions inside the Miller loop gradients and the final
exponentiation — neither of which fits comfortably inside a Bitcoin Script
budget. Witness-assisted verification moves both operations off-chain: the
prover supplies the per-iteration Miller loop gradients and four Fp12
witnesses (`f^-1`, `f2^x`, `f2^(x^2)`, `f2^(x^3)`) alongside the proof.
The on-chain script only has to check that the supplied witnesses are
locally consistent (multiplications, squarings, and Frobenius maps, all
cheap) and that the resulting pairing product equals one. The prepared
public-input accumulator (`IC[0] + Σ pubⱼ · IC[j+1]`) is also computed
off-chain, so the script never has to run variable-base G1 scalar
multiplication either.

This package is the off-chain half of that protocol.

## Use cases

- **SP1 proof verification on BSV.** SP1's Groth16 BN254 prover produces
  a `raw_proof` blob and a `vk.json` with the β/γ/δ points pre-negated to
  match the SP1 Solidity verifier convention. This package loads both
  verbatim and generates a witness that plugs directly into the Rúnar
  verifier script.
- **Custom Groth16 circuits via gnark.** If you are producing proofs from
  a gnark circuit (and not going through SP1), use
  `NewVerifyingKeyFromPositive` with the raw α/β/γ/δ affine points from
  gnark's Groth16 verifying key — it negates β/γ/δ internally — and
  `GnarkProofToWitnessInputs` with the `Ar`, `Bs`, `Krs` fields of the
  gnark proof.
- **Synthetic/test Groth16 instances.** The same gnark path is used by
  the trivial-proof script tests in this package, which build VKs from
  small generator multiples and use them as a fast regression gate for
  the verifier math.

## Quick start — SP1 path

```go
package main

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/icellan/runar/compilers/go/codegen"
    "github.com/icellan/runar/packages/runar-go/bn254witness"
)

func main() {
    fixDir := filepath.Join("tests", "vectors", "sp1", "v6.0.0")

    // 1. Load the VK. β/γ/δ are already negated in the file — this is a
    //    pure deserialization step with no transformation.
    vk, err := bn254witness.LoadSP1VKFromFile(filepath.Join(fixDir, "vk.json"))
    if err != nil {
        panic(err)
    }

    // 2. Parse the raw Groth16 proof bytes. The gnark-native G2 byte
    //    layout is imag-first; this helper swaps to Rúnar (real, imag).
    rawHex, err := os.ReadFile(filepath.Join(fixDir, "groth16_raw_proof.hex"))
    if err != nil {
        panic(err)
    }
    proof, err := bn254witness.ParseSP1RawProof(strings.TrimSpace(string(rawHex)))
    if err != nil {
        panic(err)
    }

    // 3. Load public inputs (one decimal scalar per line).
    publicInputs, err := bn254witness.LoadSP1PublicInputs(
        filepath.Join(fixDir, "groth16_public_inputs.txt"),
    )
    if err != nil {
        panic(err)
    }

    // 4. Run the off-chain witness generator. This performs the triple
    //    Miller loop with gradient capture, the prepared-inputs MSM, and
    //    the final exponentiation witness computation.
    w, err := bn254witness.GenerateWitness(vk, proof, publicInputs)
    if err != nil {
        panic(err)
    }

    // 5. Precompute MillerLoop(α, -β). The verifier multiplies this
    //    constant into the triple Miller loop accumulator before the
    //    single shared final exponentiation, so it must be baked into
    //    the codegen config (not the witness).
    alphaNegBetaFp12, err := bn254witness.PrecomputeAlphaNegBeta(vk.AlphaG1, vk.BetaNegG2)
    if err != nil {
        panic(err)
    }

    // 6. Emit the verifier script. Note that this is usually hidden
    //    behind helpers.BuildGroth16WALockingScript in deployment code.
    config := codegen.Groth16Config{
        ModuloThreshold:  0, // schoolbook bignum is slow; see Performance notes
        AlphaNegBetaFp12: alphaNegBetaFp12,
        GammaNegG2:       vk.GammaNegG2,
        DeltaNegG2:       vk.DeltaNegG2,
    }
    var verifierOps []codegen.StackOp
    codegen.EmitGroth16VerifierWitnessAssisted(func(op codegen.StackOp) {
        verifierOps = append(verifierOps, op)
    }, config)

    // 7. The unlocking script is the witness pushes, in the order
    //    ToStackOps emits them.
    witnessOps := w.ToStackOps()

    fmt.Printf("witness ops=%d  verifier ops=%d\n", len(witnessOps), len(verifierOps))
}
```

For deploying and spending, use `integration/go/helpers`:

- `helpers.BuildGroth16WALockingScript(config)` takes a `codegen.Groth16Config`
  (produced in step 6) and returns the locking script hex for the UTXO.
- `helpers.BuildGroth16WAUnlockingScript(w)` takes a `*bn254witness.Witness`
  (produced in step 4) and returns the unlocking script hex for the spending
  transaction.

## Conventions

### Fp2 ordering

Rúnar stores Fp2 elements as `(real, imaginary)` — real part first. This
matches gnark-crypto's in-memory `E2` type (`A0 = real`, `A1 = imag`) and
the `_0` / `_1` naming used by SP1's Solidity verifier. It does NOT match
the byte layout gnark-crypto uses when writing G2 points to disk (that
format is imag-first). The converters in this package do the right thing
for each source:

| Source                           | Swap needed? | Converter                                              |
| -------------------------------- | ------------ | ------------------------------------------------------ |
| gnark-crypto in-memory affine    | no           | `GnarkVKToWitnessInputs` / `GnarkProofToWitnessInputs` |
| gnark-crypto `WriteRawTo` bytes  | yes          | `ParseSP1RawProof` (handles SP1 raw proof layout)      |
| Rúnar SP1 `vk.json`              | no (schema)  | `LoadSP1VKFromFile`                                    |

### Negation convention

The emitted verifier uses the SP1 rearrangement of Groth's 2016 equation:

    e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) = 1

so β, γ, and δ are stored PRE-NEGATED in `VerifyingKey.BetaNegG2`,
`GammaNegG2`, `DeltaNegG2`. α is positive. If you are starting from
positive β/γ/δ (e.g. a gnark-built VK), use `NewVerifyingKeyFromPositive`
which applies the negation for you. For SP1 inputs the `vk.json` already
stores the negated values verbatim and `LoadSP1VKFromFile` is a pure
deserializer.

### Precomputed Miller loop vs. final pairing value

`PrecomputeAlphaNegBeta` returns the **pre-final-exponentiation** Miller
loop value for the pair `(α, -β)`, not the post-final-exp GT element. The
verifier multiplies this constant into its own Miller loop accumulator
*before* running the shared final exponentiation, so feeding it a GT
element would require `FinalExp(pre · post) == 1`, which generally fails.
Always use `PrecomputeAlphaNegBeta` — never call `gnark.Pair` and pass
its result.

### Stack layout

`Witness.ToStackOps` emits pushes in the following order (bottom of stack
first, top of stack last):

1. `q` — the BN254 field prime, as a safety sentinel the verifier checks.
2. Miller loop gradients — interleaved per iteration as `(d1, d2, d3, a1?, a2?, a3?)`
   where `dₖ` are the doubling gradients for pair `k` and `aₖ` are the
   addition gradients (present only for non-zero NAF digits).
3. Final exponentiation witnesses — 4 × 12 = 48 Fp values for `f^-1`, `a`, `b`, `c`.
4. Prepared inputs — 2 Fp values for the accumulator G1 point `(x, y)`.
5. Proof points — A `(x, y)`, B `(x0, x1, y0, y1)`, C `(x, y)`.

The emitted verifier expects this layout exactly. Do not rearrange.

## Performance notes

### ModuloThreshold

The `codegen.Groth16Config.ModuloThreshold` field controls which bignum
arithmetic strategy the emitted script uses:

- **`ModuloThreshold: 0`** — use Bitcoin Script's native `OP_MOD` /
  `OP_MUL` / `OP_DIV` for Fp reductions. This produces a large script
  (~700K ops) but executes fast on the BSV node's production interpreter.
  **This is the right choice for real execution.**
- **`ModuloThreshold: 2048`** — fall back to a schoolbook bignum
  multiply-then-reduce routine for large intermediate values. This
  produces a smaller script but is dramatically slower on the go-sdk
  interpreter (minutes instead of seconds) because the interpreter's
  bignum ops are O(n²). **Do not use this for anything timing-sensitive
  or for interpreter runs.**

All tests in this package and in `integration/go/` use
`ModuloThreshold: 0`.

### Witness generation cost

The off-chain witness generator itself is cheap — tens of milliseconds
per proof, dominated by gnark-crypto's Fp12 exponentiations inside the
final exponentiation step. Regenerating witnesses on every spend is
entirely practical.

## Known limitations

- **SP1 raw proof format assumes commitment-free proofs.** `ParseSP1RawProof`
  decodes the 324-byte `raw_proof` output of gnark-crypto's
  `groth16_bn254.Proof.WriteRawTo` and asserts that the Pedersen
  commitment count is zero. All SP1 v6 proofs are commitment-free, so
  this holds in practice, but proofs produced by other gnark users that
  carry commitments will be rejected by the parser.
- **No compressed-point support.** The raw proof parser accepts only the
  uncompressed G1/G2 encoding. SP1 emits uncompressed, so this is a
  non-issue for SP1, but downstream users of gnark who write out
  compressed proofs will need to decompress before calling `ParseSP1RawProof`.
- **Witness size.** For SP1 v6 proofs the witness adds ~470 Fp values to
  the stack (≈15 KB of push data). The verifier script itself is
  ~500 KB. The resulting spending transaction is large but well under
  the BSV node's policy limits on regtest/mainnet.

## Reference fixtures

A complete SP1 v6.0.0 Groth16 fixture suitable for drop-in testing is
checked in at `tests/vectors/sp1/v6.0.0/`:

- `vk.json` — the verifying key, with β/γ/δ pre-negated.
- `groth16_raw_proof.hex` — the 324-byte `raw_proof` blob.
- `groth16_public_inputs.txt` — five decimal public input scalars.
- `groth16_encoded_proof.hex` — the full Solidity-calldata proof for
  cross-checking against SP1's on-chain verifier.

See `tests/vectors/sp1/v6.0.0/README.md` for provenance and regeneration
instructions. The `example_test.go` in this package uses these fixtures
as the canonical runnable example.

## Related packages

- `compilers/go/codegen` — emits the on-chain verifier script
  (`EmitGroth16VerifierWitnessAssisted`) and exposes the NAF / field
  prime constants this package must stay aligned with
  (`Bn254SixXPlus2NAF`, `Bn254FieldPrime`).
- `integration/go/helpers/groth16.go` — wraps `ToStackOps` to build
  unlocking scripts and wraps `EmitGroth16VerifierWitnessAssisted` to
  build locking scripts, using the raw Bitcoin Script push-data encoder.
- `integration/go/groth16_wa_test.go` — end-to-end regtest test that
  deploys the verifier, spends it with an SP1 v6 proof, and confirms
  the transaction is accepted by a BSV node.

## API summary

Types:

- `Witness` — the complete push sequence the verifier expects.
- `VerifyingKey` — α, β⁻, γ⁻, δ⁻, IC.
- `Proof` — A, B, C.
- `SP1VKFile` — the `vk.json` schema (exposed so downstream tools that
  need to generate or inspect the file can share the types).

Core:

- `GenerateWitness(vk, proof, publicInputs) (*Witness, error)`
- `(*Witness).ToStackOps() []codegen.StackOp`

Precompute:

- `PrecomputeAlphaNegBeta(alphaG1, betaNegG2) ([12]*big.Int, error)`

Gnark converters:

- `GnarkVKToWitnessInputs(alpha, betaNeg, gammaNeg, deltaNeg, ic) VerifyingKey`
- `NewVerifyingKeyFromPositive(alpha, beta, gamma, delta, ic) VerifyingKey`
- `GnarkProofToWitnessInputs(ar, bs, krs) Proof`
- `G1AffineToBig(p) [2]*big.Int`
- `G2AffineToBig(p) [4]*big.Int`

SP1 loaders:

- `LoadSP1VKFromFile(path) (VerifyingKey, error)`
- `ParseSP1RawProof(hex) (Proof, error)`
- `LoadSP1PublicInputs(path) ([]*big.Int, error)`

Everything else in the package is internal (lowercase) and subject to
change without notice.
