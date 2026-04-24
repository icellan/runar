# minimal-guest fixture

The smallest self-contained STARK proof the on-chain verifier can
consume. Targets Plonky3's `fib_air.rs` Fibonacci AIR with the SP1
v6.0.2-pinned KoalaBear + TwoAdicFriPcs + Poseidon2 DuplexChallenger
config.

## Config (pinned)

```rust
Field:            KoalaBear
Extension:        KoalaBearExt4   // (x⁴ - 3)
Hash / sponge:    Poseidon2KoalaBear (16-state, rate=8)
PCS:              TwoAdicFriPcs
log_blowup:       1
num_queries:      2
merkle_depth:     4    // derived from trace height
sumcheck_rounds:  log2(trace_height)
log_final_poly_len: 0
commit_pow_bits:  0
query_pow_bits:   0
max_log_arity:    1
```

At these parameters the proof is small (~few KB) and the on-chain
verifier fits comfortably under PoC script-size targets. Security is
~40 bits — sufficient for end-to-end correctness testing, **not** for
mainnet soundness. Production parameters
(num_queries=100, merkle_depth~20, pow_bits=16) land in Phase 2 with
the `evm-guest` fixture.

## AIR (matches Plonky3 `uni-stark/tests/fib_air.rs`)

2-column AIR:
- Columns: `left`, `right`.
- Public inputs: `a`, `b`, `x` (initial left, initial right, final right).
- Constraints:
  - First row: `left = a`, `right = b`.
  - Transition: `left' = right`, `right' = left + right`.
  - Last row: `right = x`.

The test fixture uses 8-row trace: `a=0, b=1, x=fib(7)=21`.

## Regeneration

**Prerequisites**: Plonky3 source checked out at the SP1-pinned commit
(see `../README.md` §Upstream pinning) and Rust 1.75+.

```bash
# 1. Clone Plonky3 at the pinned commit.
git clone https://github.com/Plonky3/Plonky3 /tmp/plonky3
cd /tmp/plonky3
git checkout <pinned-sha>   # find via SP1 Cargo.lock

# 2. Port uni-stark/tests/fib_air.rs to KoalaBear (upstream test uses
#    BabyBear). A patch is staged in
#    tests/vectors/sp1/fri/minimal-guest/regen.patch (to be landed
#    alongside the fixture bytes).
git apply <runar>/tests/vectors/sp1/fri/minimal-guest/regen.patch

# 3. Extend the test to write proof.bin + vk.bin + public_values.bin
#    using bincode::serialize_into. Harness lives at
#    tests/vectors/sp1/fri/minimal-guest/regen.rs (also staged).

# 4. Run the test.
cargo test -p p3-uni-stark --test fib_air_koalabear_dump -- --nocapture

# 5. Copy outputs back.
cp target/tmp/fib_proof.bin   <runar>/tests/vectors/sp1/fri/minimal-guest/proof.bin
cp target/tmp/fib_vk.bin      <runar>/tests/vectors/sp1/fri/minimal-guest/vk.bin
cp target/tmp/fib_public.bin  <runar>/tests/vectors/sp1/fri/minimal-guest/public_values.bin

# 6. Derive hex-encoded sidecars.
xxd -p -c 0 proof.bin          > proof.hex         # optional convenience
xxd -p -c 0 public_values.bin  > public_values.hex
# keccak256 of vk.bin (single line, no 0x prefix):
keccak-256sum vk.bin | awk '{print $1}' > vk_hash.hex
```

## Files (populated in Phase 2)

| File                    | Size target | Notes                              |
|-------------------------|-------------|------------------------------------|
| proof.bin               | ~4 KB       | bincode-encoded FriProof           |
| vk.bin                  | ~256 B      | bincode-encoded StarkVerifyingKey  |
| vk_hash.hex             | 64 chars    | keccak256(vk.bin), lowercase hex   |
| public_values.hex       | 24 chars    | three u32_le values (a, b, x)      |
| README.md               | —           | this file                          |
| regen.patch             | —           | Plonky3-tree patch (Phase 2)       |
| regen.rs                | —           | test harness source (Phase 2)      |
