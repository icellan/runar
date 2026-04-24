# Corruption fixtures — negative verifier tests

For each corruption below the verifier must fail `OP_VERIFY` at a
specific detection point (documented in `docs/sp1-fri-verifier.md` §6).
Produced programmatically from `minimal-guest/` by byte-level
mutation — no fresh prover run required. A small Go regen script
lands alongside the base fixture in Phase 2 (`gen.go` in this
directory).

## Corruptions

| Directory               | Mutation                                                 | Expected reject at |
|-------------------------|----------------------------------------------------------|--------------------|
| `bad_merkle/`           | Flip one byte in a sibling digest of the first Merkle path | Merkle root recompute |
| `bad_folding/`          | Change one FRI query opened evaluation                   | Colinearity check |
| `bad_final_poly/`       | Change the single final-poly Ext4 coefficient            | Final-poly equality |
| `wrong_public_values/`  | Flip one byte of `public_values.hex`                     | Transcript divergence |
| `bad_vk/`               | Use VK hash from a different guest program               | Transcript divergence |
| `truncated/`            | Strip the last 100 bytes of `proof.bin`                  | Push-and-hash binding |
| `wrong_program/`        | Minimal-guest proof + EVM-guest VK hash                  | Transcript divergence |
| `all_zeros/`            | 200 KB of `0x00` as proof.bin                            | bincode length / hash |

## Each subdirectory contains

- The single mutated file (`proof.bin` or `public_values.hex` or
  `vk_hash.hex` — whichever the corruption targets).
- An unchanged copy of the other two fixture files, so the test
  driver can load `(proof.bin, public_values.hex, vk_hash.hex)` from
  one directory.
- A `README.md` naming the exact byte offset + original byte + mutated
  byte, for reproducibility.

## Generator script (Phase 2)

```bash
cd tests/vectors/sp1/fri/corruptions
go run ./gen.go --base ../minimal-guest --out .
```

Produces all eight subdirectories from a single `minimal-guest/`
input. Deterministic — same input always yields same corruptions.
