# runar-cli

**Command-line tool for compiling, testing, deploying, and managing Rúnar smart contracts.**

The CLI wraps the compiler, test runner, and SDK into a single `runar` command for everyday development workflow.

---

## Installation

```bash
# Global install
pnpm add -g runar-cli

# Or use via npx
npx runar-cli compile MyContract.runar.ts
```

---

## Commands

### `runar init [name]`

Scaffold a new Rúnar project.

```bash
runar init my-contract
```

### `runar compile <files...>`

Compile one or more contract files to Bitcoin Script.

```bash
# Compile a single file
runar compile contracts/P2PKH.runar.ts

# Compile multiple files
runar compile contracts/*.runar.ts

# Output to a specific directory
runar compile contracts/P2PKH.runar.ts -o ./out

# Include IR in artifact
runar compile contracts/P2PKH.runar.ts --ir

# Print ASM to stdout
runar compile contracts/P2PKH.runar.ts --asm
```

**Options:**

| Flag | Description | Default |
|---|---|---|
| `-o, --output <dir>` | Output directory for artifacts | `./artifacts` |
| `--ir` | Include ANF IR in the artifact | off |
| `--asm` | Print ASM to stdout | off |

### `runar test [pattern]`

Run contract tests.

```bash
# Run all tests
runar test

# Run tests matching a pattern
runar test P2PKH
```

### `runar deploy <artifact>`

Deploy a compiled contract to the BSV network.

```bash
runar deploy ./artifacts/P2PKH.json \
  --network testnet \
  --key cRkL4...
```

**Options:**

| Flag | Description | Default |
|---|---|---|
| `--network <net>` | `mainnet` or `testnet` | (required) |
| `--key <wif>` | WIF-encoded private key for signing | (required) |
| `--satoshis <n>` | Satoshis to lock in the contract UTXO | `10000` |

### `runar verify <txid>`

Verify a deployed contract by fetching the transaction and checking the locking script against the artifact.

```bash
runar verify abc123def456... --artifact ./artifacts/P2PKH.json --network testnet
```

**Options:**

| Flag | Description |
|---|---|
| `--artifact <path>` | Path to the compiled artifact for comparison (required) |
| `--network <net>` | Network to query (required) |

---

## Example Workflow

```bash
# 1. Create a new project
runar init my-token

# 2. Compile
runar compile contracts/MyToken.runar.ts --ir

# 3. Run tests
runar test

# 4. Deploy to testnet
runar deploy ./artifacts/MyToken.json \
  --network testnet \
  --key cRkL4...

# 5. Verify the deployment
runar verify <txid> --artifact ./artifacts/MyToken.json --network testnet
```
