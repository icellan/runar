# Rust Integration Tests

Integration tests for the Runar Rust compiler and SDK against the Runar contract
suite (compile-only) and, optionally, a live Bitcoin regtest node (on-chain
deploy/call).

## Test Modes

Tests are split into two tiers:

### 1. Default (offline) — 15 tests

Pure compile / script-size checks. They exercise the Rust compiler pipeline and
assert on artifact shape, script length, etc. No network or regtest node
required. These run on every `cargo test`.

```
cargo test
```

Tests that run by default include:

- `test_convergence_proof_compile`
- `test_auction_compile`
- `test_escrow_compile`
- `test_covenant_vault_compile`
- `test_fungible_token_compile`
- `test_function_patterns_compile`
- `test_nft_compile`
- `test_oracle_price_feed_compile`
- `test_post_quantum_wallet_compile` / `_script_size`
- `test_schnorr_zkp_compile` / `_script_size`
- `test_sphincs_wallet_compile` / `_script_size`
- `test_tic_tac_toe_compile`

### 2. Opt-in (on-chain) — 113 tests gated by `regtest` feature

Tests that deploy contracts and spend UTXOs on a local Bitcoin regtest node.
They require a reachable RPC endpoint (default `http://localhost:18332`) and
are gated with `#[cfg_attr(not(feature = "regtest"), ignore)]` so they are
silently ignored when the feature is off.

```
# 1. Start the regtest node from the repo root:
./integration/regtest.sh start

# 2. Run the gated tests:
cd integration/rust
cargo test --features regtest
```

This runs all 128 tests (15 default + 113 gated). To run only the on-chain
(gated) set without the offline tests, leave the feature off and pass
`-- --ignored`:

```
cargo test -- --ignored   # run only the on-chain tests (regtest node required)
```

## Environment Variables

| Variable   | Default                  | Description               |
| ---------- | ------------------------ | ------------------------- |
| `RPC_URL`  | `http://localhost:18332` | Bitcoin JSON-RPC endpoint |
| `RPC_USER` | `bitcoin`                | RPC username              |
| `RPC_PASS` | `bitcoin`                | RPC password              |

## File Layout

```
integration/rust/
  Cargo.toml            # defines the `regtest` feature
  tests/
    integration.rs      # test harness entry — declares all submodules
    helpers/            # compile helpers, RPC client, wallet funding, etc.
    <contract>.rs       # per-contract test module
```

Each per-contract file mixes offline compile tests (run by default) with
on-chain tests (gated). The module-level doc comment in each file explains the
gating convention.
