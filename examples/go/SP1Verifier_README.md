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
  --name SP1Verifier
```

The command prints the emitted script size (~718 KB with the default
`--modulo-threshold 0`) and the SHA-256 digest of the source VK JSON, and
writes a standard Rúnar artifact with the verifier pre-baked for this VK.

The resulting `*.runar.json` file can be loaded by any Rúnar SDK (TS, Go,
Rust, Python) as a stateless contract. Spending a UTXO that is locked with
the verifier script requires an unlock that matches the stack layout
produced by `bn254witness.Witness.ToStackOps()` — proof, gradients, and
witness-assisted final exponentiation outputs — i.e. a real Groth16 proof
from SP1.

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
