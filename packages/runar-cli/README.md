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
cd my-contract
```

Creates:

```
my-contract/
+-- package.json
+-- tsconfig.json
+-- runar.config.json
+-- contracts/
|   +-- MyContract.runar.ts    # Example P2PKH contract
+-- tests/
|   +-- MyContract.test.ts    # Example test
+-- artifacts/                # Compiled output (gitignored)
```

**Options:**

| Flag | Description |
|---|---|
| `--template <name>` | Use a template: `p2pkh` (default), `stateful`, `token`, `oracle` |
| `--no-git` | Skip git initialization |

### `runar compile <files...>`

Compile one or more `.runar.ts` files to Bitcoin Script.

```bash
# Compile a single file
runar compile contracts/P2PKH.runar.ts

# Compile all contracts in a directory
runar compile contracts/*.runar.ts

# Compile with IR output
runar compile contracts/P2PKH.runar.ts --ir
```

**Options:**

| Flag | Description | Default |
|---|---|---|
| `--outdir <dir>` | Output directory for artifacts | `./artifacts` |
| `--ir` | Include ANF IR in the artifact | `false` |
| `--source-map` | Include source location mapping | `false` |
| `--no-optimize` | Disable peephole optimizer | (optimizer on) |
| `--target <network>` | Target network: `mainnet`, `testnet` | `mainnet` |
| `--verbose` | Print detailed pass-by-pass output | `false` |

**Output:**

For each input file, produces an artifact JSON file in the output directory:

```
contracts/P2PKH.runar.ts  -->  artifacts/P2PKH.json
```

### `runar test [pattern]`

Run contract tests using Vitest.

```bash
# Run all tests
runar test

# Run tests matching a pattern
runar test P2PKH

# Run in watch mode
runar test --watch
```

**Options:**

| Flag | Description |
|---|---|
| `--watch` | Re-run tests on file changes |
| `--coverage` | Generate coverage report |
| `--verbose` | Show individual test results |

The test runner discovers test files matching `**/*.test.ts` and `**/*.spec.ts`. Tests can use the helpers from `runar-testing`:

```typescript
import { TestSmartContract, expectScriptSuccess } from 'runar-testing';

describe('P2PKH', () => {
  it('should unlock with correct sig and pubkey', () => {
    const contract = new TestSmartContract('P2PKH', {
      properties: { pubKeyHash: Addr('89abcdef...') },
    });
    const result = contract.call('unlock', {
      sig: Sig('3044...'),
      pubKey: PubKey('02abc...'),
    });
    expect(result.success).toBe(true);
  });
});
```

### `runar deploy <artifact>`

Deploy a compiled contract to the BSV network.

```bash
runar deploy ./artifacts/P2PKH.json \
  --network testnet \
  --key cRkL4... \
  --satoshis 10000 \
  --params '{"pubKeyHash": "89abcdef0123456789abcdef0123456789abcdef"}'
```

**Options:**

| Flag | Description | Default |
|---|---|---|
| `--network <net>` | `mainnet` or `testnet` | `testnet` |
| `--key <wif>` | WIF-encoded private key for signing | (required) |
| `--satoshis <n>` | Satoshis to lock in the contract UTXO | `10000` |
| `--params <json>` | Constructor parameters as JSON | (from artifact) |
| `--fee-rate <n>` | Fee rate in satoshis per byte | (auto from network) |
| `--dry-run` | Build the transaction but do not broadcast | `false` |

**Output:**

```
Compiling: P2PKH
Deploying to testnet...
Transaction: abc123def456...
Output index: 0
Locking script: 76a914...88ac
Amount: 10000 satoshis
```

### `runar verify <txid>`

Verify a deployed contract by fetching the transaction and checking the locking script against the artifact.

```bash
runar verify abc123def456... --artifact ./artifacts/P2PKH.json --network testnet
```

**Options:**

| Flag | Description |
|---|---|
| `--artifact <path>` | Path to the compiled artifact for comparison |
| `--network <net>` | Network to query |
| `--output-index <n>` | Transaction output index to verify (default: 0) |

---

## Configuration

Create a `runar.config.json` in the project root:

```json
{
  "compilerOptions": {
    "outDir": "./artifacts",
    "optimize": true,
    "includeIR": false,
    "includeSourceMap": false,
    "target": "mainnet"
  },
  "contracts": [
    "contracts/**/*.runar.ts"
  ],
  "testPattern": [
    "tests/**/*.test.ts"
  ]
}
```

CLI flags override config file values.

---

## Example Workflow

Start to finish, from project creation to testnet deployment:

```bash
# 1. Create a new project
runar init my-token --template token
cd my-token

# 2. Edit the contract
vim contracts/MyToken.runar.ts

# 3. Compile
runar compile contracts/MyToken.runar.ts --ir

# 4. Run tests
runar test

# 5. Deploy to testnet
runar deploy ./artifacts/MyToken.json \
  --network testnet \
  --key cRkL4... \
  --params '{"owner": "02abc...", "supply": "1000000"}'

# 6. Verify the deployment
runar verify <txid> --artifact ./artifacts/MyToken.json --network testnet
```
