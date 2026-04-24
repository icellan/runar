# evm-guest fixture

A real SP1 v6.0.2 STARK proof of BSVM's revm EVM guest program.
Drives Phase 2 measurement: verifier script size, peak stack depth,
execution time at production parameters
(num_queries=100, merkle_depth=~20, pow_bits=16).

## Source

- Guest program: `../bsv-evm/guest/evm/src/main.rs` at the
  SP1-v6.0.2-pinned commit of the bsv-evm repo.
- Input: a minimal EVM transaction trace. Canonical input shipped as
  `input.bin` alongside the fixture once generated.

## Regeneration

**Prerequisites**: SP1 SDK toolchain installed via `sp1up`. Must be
SP1 v6.0.2 exactly — newer versions may have backward-incompatible
STARK proof format changes.

```bash
# 1. Install the SP1 SDK toolchain pinned to v6.0.2.
curl -L https://sp1.succinct.xyz | bash
sp1up --version 6.0.2

# 2. Check out bsv-evm at the pinned commit.
cd ~/gitcheckout/bsv-evm
git checkout <pinned-sha>    # see bsv-evm/RUNAR-FRI-VERIFIER.md §2.1

# 3. Generate the proof.
cd ~/gitcheckout/bsv-evm/guest/evm
cargo prove build --release
cargo prove prove \
  --input ../../tests/sp1/input.bin \
  --output /tmp/sp1_evm_stark.bin \
  --mode stark           # NOT groth16 — we want the inner STARK proof

# 4. Extract the STARK proof payload from SP1's wrapping.
#    (SP1 wraps STARK proofs in a metadata envelope; the inner Plonky3
#    FriProof is at a known offset. See SP1 `crates/sdk/src/proof.rs`
#    ShardProof serialization.)
# A small extractor lives at
#   tests/vectors/sp1/fri/evm-guest/extract.rs (staged for Phase 2).
cargo run --bin sp1-extract-stark \
  /tmp/sp1_evm_stark.bin \
  ~/gitcheckout/runar/tests/vectors/sp1/fri/evm-guest/proof.bin

# 5. Dump public values + VK.
sp1-sdk dump-public-values /tmp/sp1_evm_stark.bin \
  > ~/gitcheckout/runar/tests/vectors/sp1/fri/evm-guest/public_values.hex
sp1-sdk dump-vk-hash \
  > ~/gitcheckout/runar/tests/vectors/sp1/fri/evm-guest/vk_hash.hex
```

Expected proof size: 80–200 KB depending on trace height and
constraint density of the specific input. Commit under git-LFS if
the file exceeds 100 KB (the repo's threshold).

## Files (populated in Phase 2)

| File                    | Size target  | Notes                               |
|-------------------------|--------------|-------------------------------------|
| proof.bin               | 80–200 KB    | bincode-encoded inner FriProof      |
| vk_hash.hex             | 64 chars     | keccak256 of the EVM guest VK       |
| public_values.hex       | 256 chars    | pre_state_root, post_state_root, etc|
| input.bin               | varies       | the EVM tx trace the guest proved   |
| README.md               | —            | this file                           |
| extract.rs              | —            | STARK-payload extractor (Phase 2)   |
