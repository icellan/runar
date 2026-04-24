# SP1 STARK / FRI test vectors

Consumed by the on-chain `runar.VerifySP1FRI` verifier (see
`docs/sp1-fri-verifier.md`) and by the Go reference verifier once it
lands. Fixtures are *regeneratable* — this directory ships READMEs
describing the exact commands to produce each file; the bytes
themselves land in a follow-up PR alongside the verifier codegen
body.

## Layout

```text
tests/vectors/sp1/fri/
  minimal-guest/            # PoC fixture — Plonky3 fib_air, KoalaBear
    proof.bin               # bincode-encoded Plonky3 FriProof
    public_values.hex       # lowercase hex, no 0x prefix
    vk_hash.hex             # 64 hex chars (keccak256 of the VK)
    README.md               # trace width, degree_bits, params, regen cmd
  evm-guest/                # Phase 2 fixture — real SP1 EVM-guest
    ...same four files...
  corruptions/
    bad_merkle/proof.bin    # one byte flipped in a sibling hash
    bad_folding/proof.bin   # one FRI query evaluation mutated
    bad_final_poly/proof.bin
    wrong_public_values/public_values.hex
    bad_vk/vk_hash.hex
    truncated/proof.bin
    wrong_program/proof.bin # proof for minimal-guest + VK for evm-guest
    all_zeros/proof.bin     # 200 KB of 0x00
```

## Status

**Phase 1 (current):** directory + READMEs only. Actual proof bytes land
with the verifier codegen body. The verifier is not end-to-end
runnable until both arrive together.

**Phase 2:** minimal-guest fixture committed; Go reference verifier
validates it; Bitcoin Script codegen emits deterministic script bytes
for that fixture. Corruption fixtures committed and rejected by the
Go reference verifier.

**Phase 3:** evm-guest fixture committed; script-size / stack-depth /
execution-time measurements recorded in
`docs/fri-verifier-measurements.md`.

## Regeneration summary

See each subdirectory's `README.md` for exact commands. High-level:

- `minimal-guest` is the **Plonky3 `fib_air.rs` test proof** with
  configuration pinned to match SP1 v6.0.2's DuplexChallenger +
  TwoAdicFriPcs + KoalaBear base field. Regeneration requires a
  checkout of Plonky3 at the SP1-pinned commit and a small test
  harness that serializes the generated proof.
- `evm-guest` is a real SP1 v6.0.2 STARK proof of the revm EVM guest
  in `../bsv-evm/guest/`. Regeneration requires a working SP1 SDK
  toolchain (`sp1up`) and is expensive (tens of minutes, large proof
  file ~100 KB+).
- Corruption fixtures are produced programmatically from the base
  `minimal-guest/proof.bin` + `vk_hash.hex` + `public_values.hex` by
  byte-level mutation. A small Go regen script under
  `tests/vectors/sp1/fri/corruptions/gen.go` produces all of them
  from the base fixture (see its companion README).

## Upstream version pinning

| Component  | Version     | Source                                     |
|------------|-------------|--------------------------------------------|
| SP1        | v6.0.2      | https://github.com/succinctlabs/sp1        |
| Plonky3    | pinned by SP1 v6.0.2 `Cargo.lock`          |  |
| KoalaBear  | Plonky3 koala-bear crate                   |  |
| Poseidon2  | Plonky3 koala-bear/src/poseidon2.rs        |  |

Any version bump MUST (a) regenerate every fixture in this tree, (b)
re-run the entire verifier test suite against the new fixtures, (c)
re-run the regtest measurement pass, (d) update
`docs/sp1-proof-format.md` §1 with the new pinned version strings.
