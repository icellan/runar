# minimal-guest fixture

The smallest self-contained STARK + FRI proof the on-chain verifier will
target. Real Plonky3 output: a Fibonacci AIR proven over KoalaBear (the
field SP1 v6.0.2 uses), config matching Plonky3's
`fib_air.rs::generate_two_adic_fixture` ported to KoalaBear.

## Files

| File                   | Size       | Notes                                                     |
|------------------------|------------|-----------------------------------------------------------|
| `proof.postcard`       | 1589 bytes | postcard-encoded `p3_uni_stark::Proof<MyConfig>`          |
| `README.md`            | —          | this file                                                 |
| `regen/Cargo.toml`     | —          | Rust fixture generator manifest (depends on Plonky3 main) |
| `regen/src/main.rs`    | —          | Fibonacci AIR + KoalaBear config + postcard dump          |

## Pinned config

```rust
Field:               KoalaBear (prime 2^31 − 2^24 + 1)
Extension:           BinomialExtensionField<KoalaBear, 4> (X⁴ − 3)
Hash / sponge:       Poseidon2-KoalaBear (16-state, rate=8)
PCS:                 TwoAdicFriPcs
log_blowup:          2
num_queries:         2
log_final_poly_len:  2
max_log_arity:       1
commit_pow_bits:     1
query_pow_bits:      1
trace:               8 rows × 2 cols (Fibonacci, pis [0, 1, 21])
```

At these parameters the proof is small (~1.6 KB) and the on-chain verifier
fits comfortably under PoC script-size targets. Security is ~40 bits —
sufficient for end-to-end correctness testing, **not** mainnet
soundness. Production parameters land in Phase 2 with the `evm-guest`
fixture.

The Poseidon2 permutation uses the canonical published constants
(`default_koalabear_poseidon2_16()`) so any verifier embedding the
SP1 v6.0.2 `KOALABEAR_POSEIDON2_RC_16_*` tables can reproduce the
permutation byte-for-byte. The off-chain Go reference verifier at
`packages/runar-go/sp1fri/` accepts this fixture end-to-end (see
`TestVerifyMinimalGuest`).

## AIR (matches Plonky3 `uni-stark/tests/fib_air.rs` port to KoalaBear)

2-column AIR:
- Columns: `left`, `right`.
- Public inputs: `a`, `b`, `x` (initial left, initial right, final right).
- Constraints:
  - First row: `left = a`, `right = b`.
  - Transition: `left' = right`, `right' = left + right`.
  - Last row: `right = x`.

The fixture uses an 8-row trace: `a=0, b=1, x=fib(7)=21`.

## Decoder validation

The Go decoder at `packages/runar-go/sp1fri/` round-trips this fixture
byte-exactly:

```bash
cd packages/runar-go/sp1fri && go test -v -run TestDecodeProofRoundTrip
```

Decoded structure:

```
degree_bits           = 3
commitments.trace     MerkleCap cap_len = 1 (single root, cap_height=0)
commitments.quotient_chunks MerkleCap cap_len = 1
commitments.random    None (non-ZK config)
opened_values.trace_local  len = 2 (Fib has 2 cols)
opened_values.trace_next   len = 2 (Fib uses transition constraints)
opened_values.quotient_chunks outer = 1 (single quotient batch)
opening_proof.commit_phase_commits = 1 (one fold step)
opening_proof.commit_pow_witnesses = 1
opening_proof.query_proofs         = 2 (num_queries=2)
opening_proof.final_poly           = 4 (2^log_final_poly_len = 2^2)
```

KoalaBear elements in the postcard wire are in **Plonky3 Montgomery form**
(raw u32 the prover serialised). On-chain Bitcoin Script arithmetic uses
canonical values; `packages/runar-go/sp1fri/montgomery.go` provides the
boundary conversion helpers.

## Regeneration

```bash
# Pulls Plonky3 (main branch) on first build; takes ~3 min.
cd tests/vectors/sp1/fri/minimal-guest/regen
ulimit -n 65536            # macOS default 256 is too low for the dep tree
cargo build --release
./target/release/runar-fixture-gen ../proof.postcard
```

The `regen/` directory stays out of the Go workspace because it depends
on Rust toolchain + crates.io / GitHub network access. It is documentation
+ build infrastructure, not a runtime build target.

## Upstream version pinning

| Component  | Version                        | Source                               |
|------------|--------------------------------|--------------------------------------|
| Rust       | 1.94.0                         | rustup stable                         |
| Plonky3    | `main` branch (commit 794faa1) | github.com/Plonky3/Plonky3            |
| postcard   | 1.x                            | crates.io                             |

Any version bump MUST regenerate this fixture, re-run the Go decoder
round-trip test, and update the version table here.
