# SP1 v6.0.0 Groth16 Verifying Key Example

This directory contains a ready-to-use BN254 Groth16 verifying key for the
[SP1 zkVM](https://github.com/succinctlabs/sp1) v6.0.0 release:

- `SP1Verifier.groth16.vk.json` — the VK in the Rúnar / SP1 convention
  (β, γ, δ pre-negated on the G2 side, Fp2 pairs stored as `(x0=real, x1=imag)`).

## Compiling to a Rúnar artifact

```bash
# From the repo root
go run ./compilers/go groth16-wa \
  --vk examples/go/SP1Verifier.groth16.vk.json \
  --out examples/go/SP1Verifier.runar.json \
  --name SP1Verifier \
  --pub 66357586313644860799771794752501372267945898538662503063451090361394363786 \
  --pub 847835036251654310728024989634801415315612733526607753937102182742950003855 \
  --pub 0 \
  --pub 248831628400185611740479071450564250193912070693925013182243127282342200944 \
  --pub 0
```

The `--pub` values pin the five public inputs the verifier accepts (the
command refuses to emit an unbound verifier). It prints the emitted script
size (~1.5 MB with the default `--modulo-threshold 0`) and the SHA-256
digest of the source VK JSON, and writes a standard Rúnar artifact with the
verifier pre-baked for this VK and statement.

The resulting `*.runar.json` file can be loaded by any Rúnar SDK (TS, Go,
Rust, Python) as a stateless contract. Spending a UTXO that is locked with
the verifier script requires an unlock that matches the stack layout
produced by `bn254witness.BuildFromProofWithInputs(...).ToStackOps()` —
gradients, the residue witness (c, c⁻¹, s) that replaces the final
exponentiation, the public inputs and the proof — followed by the owner's
signature, i.e. a real Groth16 proof from SP1.

See `spec/groth16_wa_vk.schema.json` for the full input JSON schema.

## Origin

The VK in this file was extracted from SP1's reference Solidity verifier
at `~/.sp1/circuits/groth16/v6.0.0/Groth16Verifier.sol`. The test fixture
used to regenerate it lives in `tests/vectors/sp1/v6.0.0/` along with a
real proof and public inputs. This example file is kept separate so
end-users can discover it in the examples directory without having to
know about the internal test vectors.

To regenerate this file, copy it from the fixture:

```bash
cp tests/vectors/sp1/v6.0.0/vk.json examples/go/SP1Verifier.groth16.vk.json
```

Because β, γ, δ are already pre-negated in the source file, no
transformation is needed — the data drops in verbatim.
