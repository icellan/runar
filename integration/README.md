# Integration Tests

End-to-end integration tests that deploy and spend Runar contracts on a real Bitcoin node. Tests are organized by language (Go, TypeScript, Rust, Python, Ruby, Zig) — each suite uses its own compiler and SDK for deployment/calling.

Two node backends are supported:

- **SV Node** — Bitcoin SV node with built-in wallet (default)
- **Teranode** — BSV's microservices-based node implementation

## Quick Start

### SV Node

```bash
# Start node, run tests, stop node
pnpm integration:svnode:run

# Or step by step:
pnpm integration:svnode:start
pnpm integration:go          # Go tests
pnpm integration:ts          # TypeScript tests
pnpm integration:svnode:stop
pnpm integration:svnode:clean    # remove all data
```

### Teranode

```bash
# Start node, run tests, stop node (clean start)
pnpm integration:teranode:run

# Or step by step:
pnpm integration:teranode:start   # starts Docker services + mines 10101 blocks
pnpm integration:teranode
pnpm integration:teranode:stop
pnpm integration:teranode:clean   # remove all data + volumes
```

## Test Suites

### Go (`integration/go/`)

Full-featured tests using the Go compiler and SDK. Includes raw transaction construction for contracts that require ECDSA signatures in the unlocking script.

```bash
cd integration/go && go test -tags integration -v -timeout 600s
```

### TypeScript (`integration/ts/`)

Tests using the TypeScript compiler and SDK. All contracts use the SDK's `Deploy` + `Call` path.

```bash
cd integration/ts && npx vitest run
```

### Rust (`integration/rust/`)

Tests using the Rust compiler and SDK. All contracts use the SDK's Deploy + Call path.

```bash
cd integration/rust && cargo test --release -- --ignored
```

### Python (`integration/python/`)

Tests using the Python compiler and SDK. Requires `bsv-sdk` pip package for real ECDSA signing.

```bash
cd integration/python
python3.13 -m venv .venv                # Python 3.13 (3.14 has coincurve build issues)
.venv/bin/pip install -r requirements.txt
PYTHONPATH=../../compilers/python:../../packages/runar-py .venv/bin/pytest -v
```

### Run All Suites

```bash
# Run all suites (node must be running)
pnpm integration:all

# Start node, run all, stop node
pnpm integration:all:run
```

## Contracts Tested

| Contract | Type | Go | TS | Rust | Python | Ruby | Zig | Key Feature |
|----------|------|----|----|------|--------|------|-----|-------------|
| P2PKH | Stateless | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | ECDSA checkSig |
| Escrow | Stateless | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Multi-method, multi-signer |
| Counter | Stateful | Deploy + Call | Deploy + Call | Deploy + Call | Deploy + Call | Deploy + Call | Deploy + Call | OP_PUSH_TX, state transitions |
| MathDemo | Stateful | Deploy + Call | Deploy + Call | Deploy + Call | Deploy + Call | Deploy + Call | Deploy + Call | Built-in math functions |
| FungibleToken | Stateful | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | PubKey + balance state |
| SimpleNFT | Stateful | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Token transfer + burn |
| Auction | Stateful | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Bidding + locktime |
| CovenantVault | Stateless | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Covenant rules (SigHashPreimage) |
| OraclePriceFeed | Stateless | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Rabin signatures |
| FunctionPatterns | Stateful | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Private methods, composition |
| PostQuantumWallet | Stateless | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | WOTS+ (19KB script) |
| SPHINCSWallet | Stateless | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | SLH-DSA (188KB script) |
| SchnorrZKP | Stateless | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | EC operations, ZKP (877KB) |
| ConvergenceProof | Stateless | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | EC point arithmetic |
| EC Isolation | Stateless | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | Deploy + Spend | ecOnCurve, ecMulGen, ecAdd, ecNegate |

## Node Setup Details

### SV Node

Uses the `bitcoinsv/bitcoin-sv:latest` Docker image. A single container runs the full node in regtest mode with:

- `genesisactivationheight=1` — post-Genesis rules from block 1
- `maxscriptsizepolicy=0` / `maxscriptnumlengthpolicy=0` — unlimited script sizes
- Built-in wallet for `sendtoaddress` funding

RPC: `http://localhost:18332` (user: `bitcoin`, pass: `bitcoin`)

### Teranode

Uses `ghcr.io/bsv-blockchain/teranode:v0.13.2` with 10+ microservices in Docker Compose:

- blockchain, validator, blockassembly, blockvalidation, subtreevalidation, propagation, rpc, asset, peer
- Infrastructure: PostgreSQL, Aerospike, Kafka (Redpanda)

Key differences from SV Node:

| Feature | SV Node | Teranode |
|---------|---------|----------|
| Genesis activation | Height 1 (configurable) | Height 10000 (hardcoded in go-chaincfg) |
| Wallet | Built-in (`sendtoaddress`) | None — uses raw coinbase UTXOs |
| `getrawtransaction` verbose | `true` (bool) | `1` (int) |
| `getrawtransaction` value | BTC (e.g. 50.0) | Satoshis (e.g. 5000000000) |
| `getblock` tx list | Populated | Empty (code commented out) |
| Block format | Standard | Extended (extra varint fields + subtree hashes) |

Because Teranode's Genesis activation is hardcoded at height 10000 for regtest, the `teranode.sh start` script pre-mines 10101 blocks (10000 for Genesis + 101 for coinbase maturity). This takes ~5 minutes on first start. Subsequent `start` commands (without `clean`) skip mining if blocks already exist.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_TYPE` | `svnode` | Node backend: `svnode` or `teranode` |
| `RPC_URL` | auto | Override RPC endpoint URL |
| `RPC_USER` | `bitcoin` | RPC username |
| `RPC_PASS` | `bitcoin` | RPC password |

## Troubleshooting

**UTXO_SPENT errors**: Run `./teranode.sh clean && ./teranode.sh start` to reset all state. The coinbase UTXO counter resets each test run but Teranode remembers spent UTXOs.

**RPC timeout during mining**: The Teranode RPC timeout is set to 600s in `settings_local.conf`. The Go HTTP client also uses a 10-minute timeout.

**Tests pass on SV Node but fail on Teranode**: Check that the 10101 blocks were mined (Genesis activation). Run `./teranode.sh getblockchaininfo` to verify the block height.
