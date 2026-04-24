# Script 21 — Blackjack Webapp

A provably-fair blackjack game that uses Bitcoin SV smart contracts (compiled with Rúnar) for trustless betting. Each round deploys a `BlackjackBet` contract on-chain, with an oracle (Rabin signature) attesting to outcomes and full deck commitment for auditability.

## Prerequisites

- **Docker** — pulls `bitcoinsv/bitcoin-sv:latest` from Docker Hub
- **Go 1.26+**
- The Rúnar Go compiler (resolved via `go.work` / `replace` directive in `go.mod`)

## 1. Start the regtest node

```bash
./regtest.sh start
```

This will:
- Pull `bitcoinsv/bitcoin-sv:latest` from Docker Hub (on first run)
- Create a `regtest/n1` directory with a `bitcoin.conf` for regtest mode
- Start a `bitcoin-sv-regtest` Docker container with the data volume mounted at `/data`, exposing RPC on port `18332`

You can interact with the node directly:

```bash
./regtest.sh getblockcount
./regtest.sh generate 10
```

To stop the node:

```bash
./regtest.sh stop
```

## 2. Build the webapp

```bash
go build -o script21 .
```

## 3. Run

```bash
./script21
```

The webapp starts on port `8081` by default. Open http://localhost:8081 in a browser.

To use a different port:

```bash
PORT=9090 ./script21
```

### Environment variables

| Variable   | Default                    | Description              |
|------------|----------------------------|--------------------------|
| `PORT`     | `8081`                     | HTTP listen port         |
| `RPC_URL`  | `http://localhost:18332`   | Bitcoin node RPC URL     |
| `RPC_USER` | `bitcoin`                  | RPC username             |
| `RPC_PASS` | `bitcoin`                  | RPC password             |

## How it works

1. **New Game** — Creates house and player wallets, funds them from the regtest faucet
2. **Deal** — Shuffles a deck, commits the SHA-256 hash on-chain, deploys a `BlackjackBet` smart contract per player
3. **Player Turns** — Hit or stand
4. **Dealer Turn** — Dealer draws to 17, outcomes are determined, contracts are settled on-chain using Rabin oracle signatures
5. **Audit** — Full deck order, salt, and all transaction IDs are published on-chain for independent verification
