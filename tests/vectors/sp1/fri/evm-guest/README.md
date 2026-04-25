# evm-guest fixture

Production-scale Plonky3 KoalaBear FRI proof of a Fibonacci AIR. Drives the
Phase 2 scale-up validation of the on-chain SP1 FRI verifier:
`compilers/go/codegen/sp1_fri.go::EmitFullSP1FriVerifierBody`.

This is **NOT** a real SP1 EVM-guest STARK proof — that path requires the
SP1 SDK and bsv-evm guest source (see "Future work" below). The fixture is
the same Fibonacci AIR as `minimal-guest/` but with the production FRI
parameter tuple, which is what determines verifier cost (script size,
peak stack, wall-clock). Verifier algorithm is identical for both.

## Files

| File                   | Size       | Notes                                                     |
|------------------------|------------|-----------------------------------------------------------|
| `proof.postcard`       | 140778 B   | postcard-encoded `p3_uni_stark::Proof<MyConfig>`          |
| `README.md`            | --         | this file                                                 |
| `regen/Cargo.toml`     | --         | Rust fixture generator manifest (depends on Plonky3 main) |
| `regen/src/main.rs`    | --         | Fibonacci AIR + KoalaBear config + postcard dump          |

## Pinned config

```rust
Field:               KoalaBear (prime 2^31 - 2^24 + 1)
Extension:           BinomialExtensionField<KoalaBear, 4> (X^4 - 3)
Hash / sponge:       Poseidon2-KoalaBear (16-state, rate=8)
PCS:                 TwoAdicFriPcs
log_blowup:          1                  // production target
num_queries:         100                // production target (~100-bit security)
log_final_poly_len:  9                  // see "Codegen-helper coupling" below
max_log_arity:       1
commit_pow_bits:     16                 // production target
query_pow_bits:      16                 // production target
trace:               1024 rows × 2 cols (Fibonacci, pis [0, 1, fib(1023) mod p])
```

Public values: `[a=0, b=1, x=fib(1023) mod p = 377841674]`.

The Poseidon2 permutation uses the canonical published constants
(`default_koalabear_poseidon2_16()`) so any verifier embedding the
SP1 v6.0.2 `KOALABEAR_POSEIDON2_RC_16_*` tables can reproduce the
permutation byte-for-byte.

## Codegen-helper coupling: log_final_poly_len pinned to degreeBits - 1

The codegen orchestrator
`compilers/go/codegen/sp1_fri.go::EmitFullSP1FriVerifierBody` (line 317)
hard-codes `numRounds = 1` for the FRI commit phase. With `max_log_arity = 1`
this implies `total_log_reduction = 1`, i.e.
`degreeBits - log_final_poly_len = 1`. So `log_final_poly_len` is pinned
to `degreeBits - 1 = 9` for the 1024-row trace.

This is the _only_ knob the production-tuning had to give up versus the
canonical "`log_final_poly_len = 0` (constant final poly)" target in
`docs/sp1-fri-verifier.md` Section 4. The trade-off shifts ~512 Ext4
coefficients (= 2048 base-field elements) from the FRI commit-phase Merkle
ladder into the unlocking-script `final_poly` push layer; total prover work
stays equivalent. Lifting this restriction requires teaching
`EmitFullSP1FriVerifierBody` to compute `numRounds` from
`SP1FriVerifierParams.{DegreeBits, LogFinalPolyLen, MaxLogArity}` — a
follow-up flagged in `docs/fri-verifier-measurements.md` (Section "Bugs
flagged").

## Acceptance status

* **Off-chain reference verifier**:
  `packages/runar-go/sp1fri::VerifyWithConfig(proof, pis, evmGuestConfig)`
  accepts (`TestVerifyEvmGuest`).
* **On-chain script-VM**:
  `EmitFullSP1FriVerifierBody(emit, params)` with the production parameter
  tuple is accepted by the go-sdk Bitcoin Script interpreter
  (`TestSp1FriVerifier_AcceptsEvmGuestFixture`). Measurements logged in
  `docs/fri-verifier-measurements.md`.

## Regeneration

```bash
# Pulls Plonky3 (main branch) on first build; takes ~2 min.
cd tests/vectors/sp1/fri/evm-guest/regen
ulimit -n 65536            # macOS default 256 is too low for the dep tree
cargo build --release -j 2
./target/release/runar-evm-guest-fixture-gen ../proof.postcard
```

The generator self-verifies the proof via `p3_uni_stark::verify` before
writing the postcard, so a successful exit code implies a valid fixture.

If you change `LOG_TRACE_HEIGHT`, the generator re-derives `x_pub`
(= `fib(1024 - 1) mod p`) at run time; update the public-value constant
in `packages/runar-go/sp1fri/verify_test.go::TestVerifyEvmGuest` and
`compilers/go/codegen/sp1_fri_test.go::publicValuesEvmGuestBytes` to
match the new value the generator prints.

## Upstream version pinning

| Component  | Version                        | Source                               |
|------------|--------------------------------|--------------------------------------|
| Rust       | 1.94.0                         | rustup stable                         |
| Plonky3    | `main` branch (commit 7a689588) | github.com/Plonky3/Plonky3            |
| postcard   | 1.x                            | crates.io                             |

Any version bump MUST regenerate this fixture, re-run the off-chain and
on-chain acceptance tests, and update the version table here.

## Future work: real SP1 EVM-guest STARK proof

The original brief for this fixture was a real SP1 v6.0.2 STARK proof of
BSVM's revm EVM guest program. That requires:

1. SP1 SDK toolchain installed via `sp1up --version 6.0.2`.
2. `bsv-evm/guest/evm/` source at the SP1-pinned commit.
3. A canonical EVM transaction trace as input.
4. A small extractor to peel the STARK payload out of SP1's wrapping
   (the inner Plonky3 `FriProof` is at a known offset; see SP1's
   `crates/sdk/src/proof.rs::ShardProof` serialization).

The Phase 2 scale-up landed ahead of the SP1 SDK integration, so the
fixture above stands in for the real EVM-guest proof. The verifier
algorithm is independent of the AIR shape (as long as it's a Plonky3
KoalaBear STARK with binary FRI folding), so swapping in a real EVM-guest
proof is a fixture-replacement exercise, not a verifier change.

```bash
# Once SP1 SDK is installed (paste of the original Phase 2 plan):
curl -L https://sp1.succinct.xyz | bash
sp1up --version 6.0.2

cd ~/gitcheckout/bsv-evm
git checkout <pinned-sha>    # see bsv-evm/RUNAR-FRI-VERIFIER.md Section 2.1

cd ~/gitcheckout/bsv-evm/guest/evm
cargo prove build --release
cargo prove prove \
  --input ../../tests/sp1/input.bin \
  --output /tmp/sp1_evm_stark.bin \
  --mode stark           # NOT groth16

cargo run --bin sp1-extract-stark \
  /tmp/sp1_evm_stark.bin \
  ~/gitcheckout/runar/tests/vectors/sp1/fri/evm-guest/proof.bin

sp1-sdk dump-public-values /tmp/sp1_evm_stark.bin \
  > ~/gitcheckout/runar/tests/vectors/sp1/fri/evm-guest/public_values.hex
sp1-sdk dump-vk-hash \
  > ~/gitcheckout/runar/tests/vectors/sp1/fri/evm-guest/vk_hash.hex
```
