# runar-sdk

TypeScript SDK for deploying, calling, and reading Rúnar smart contracts on Bitcoin SV.

`runar-sdk` is the runtime layer that turns a compiled Rúnar artifact into on-chain transactions. It wraps `@bsv/sdk` for low-level transaction handling and adds Rúnar-specific behaviour: BIP-143 OP_PUSH_TX preimage construction, automatic state continuation for stateful contracts, multi-output spending, terminal-method handling, OP_CODESEPARATOR-aware sighash computation, ANF-based auto state computation, BRC-100 wallet integration, and 1sat ordinals envelopes.

The SDK does not compile contracts. Source compilation lives in `runar-compiler`. The SDK consumes the JSON artifact that the compiler produces and the SDK exposes the same public API surface as the Go, Rust, Python, Zig, Ruby, and Java SDKs (cross-SDK byte-identity is verified by the `conformance/sdk-output/` suite).

---

## Table of contents

1. [Title and overview](#runar-sdk)
2. [Table of contents](#table-of-contents)
3. [Installation](#installation)
4. [Quick start](#quick-start)
5. [Core concepts](#core-concepts)
6. [Writing a contract](#writing-a-contract)
7. [Compiling](#compiling)
8. [Deploying contracts](#deploying-contracts)
9. [Calling contract methods](#calling-contract-methods)
   - [9a. Single-signer (`call`)](#9a-single-signer-call)
   - [9b. Multi-signer (`prepareCall` / `finalizeCall`)](#9b-multi-signer-preparecall--finalizecall)
   - [9c. BRC-100 wallet signing](#9c-brc-100-wallet-signing)
10. [Stateful contracts](#stateful-contracts)
11. [UTXO and fee management](#utxo-and-fee-management)
12. [Typed contract bindings](#typed-contract-bindings)
13. [Testing](#testing)
    - [13a. Off-chain runtime simulation](#13a-off-chain-runtime-simulation)
    - [13b. Integration testing against a regtest node](#13b-integration-testing-against-a-regtest-node)
14. [Provider configuration](#provider-configuration)
15. [Full API reference](#full-api-reference)
16. [Error handling](#error-handling)
17. [Troubleshooting / FAQ](#troubleshooting--faq)
18. [Versioning and stability](#versioning-and-stability)
19. [Links](#links)

---

## Installation

```bash
pnpm add runar-sdk
# or
npm install runar-sdk
# or
yarn add runar-sdk
```

The SDK requires Node.js 18 or newer (uses native `fetch` and Web Crypto). It is published as ESM only. `@bsv/sdk` is a runtime dependency and is installed automatically.

If you also want to compile contracts in-process, install the compiler:

```bash
pnpm add runar-compiler runar-lang runar-ir-schema
```

---

## Quick start

This walkthrough deploys the canonical `Counter` stateful contract, increments its state on chain, then reads the new value back. It uses `MockProvider` so you can run it without a node.

```typescript
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile } from 'runar-compiler';
import {
  RunarContract,
  MockProvider,
  LocalSigner,
} from 'runar-sdk';

// 1. Compile the contract (in real apps you can ship the artifact JSON).
const source = readFileSync(
  resolve('examples/ts/stateful-counter/Counter.runar.ts'),
  'utf8',
);
const result = compile(source, { fileName: 'Counter.runar.ts' });
if (!result.artifact) {
  throw new Error(`Compile failed: ${JSON.stringify(result.diagnostics)}`);
}
const artifact = result.artifact;

// 2. Set up a provider and signer. MockProvider needs a funding UTXO.
const signer = new LocalSigner(
  '0000000000000000000000000000000000000000000000000000000000000001',
);
const provider = new MockProvider();
provider.addUtxo(await signer.getAddress(), {
  txid: 'aa'.repeat(32),
  outputIndex: 0,
  satoshis: 100_000,
  script: '76a914' + '00'.repeat(20) + '88ac', // any P2PKH placeholder
});

// 3. Construct the contract with its initial state (count = 0).
const counter = new RunarContract(artifact, [0n]);
counter.connect(provider, signer);

// 4. Deploy.
const { txid: deployTxid } = await counter.deploy({ satoshis: 1_000 });
console.log('deploy txid:', deployTxid);
console.log('initial count:', counter.state.count); // 0n

// 5. Call increment. The SDK auto-computes the new state from the contract's
// ANF IR, builds the OP_PUSH_TX preimage, and updates the tracked UTXO.
const { txid: callTxid } = await counter.call('increment', []);
console.log('increment txid:', callTxid);
console.log('new count:', counter.state.count); // 1n
```

For a real-network version, swap `MockProvider` for `WhatsOnChainProvider('testnet')` (with a funded testnet key) or `RPCProvider(...)` against a regtest node. See [Provider configuration](#provider-configuration).

---

## Core concepts

These terms are used throughout the rest of the README and across all seven Rúnar SDKs.

- **Artifact** (`RunarArtifact`, re-exported from `runar-ir-schema`): the compiled contract. Carries the locking-script template, ABI, state schema, constructor and code-separator slot offsets, and the ANF IR. Immutable; load from JSON or take directly from `compile(...)`.
- **Contract** (`RunarContract`, [src/contract.ts](src/contract.ts)): the runtime wrapper that binds an artifact to constructor args, tracks current state and UTXO, and produces transactions for deploy, call, prepare, and finalize.
- **Provider** (`Provider` interface, [src/providers/provider.ts](src/providers/provider.ts)): blockchain access. Reads transactions and UTXOs, broadcasts new ones, exposes a fee rate.
- **Signer** (`Signer` interface, [src/signers/signer.ts](src/signers/signer.ts)): key management. Derives a compressed public key, derives a Base58Check address, and produces BIP-143 ECDSA signatures over given subscripts.
- **Wallet** (BRC-100 `WalletClient` from `@bsv/sdk`): a browser- or extension-resident wallet that owns its keys and creates its own actions. Backs `WalletProvider` and `WalletSigner`.
- **Call**: a method invocation. Spends the contract UTXO; for stateful contracts, creates a continuation UTXO with updated state; can produce additional data outputs and terminal outputs; broadcasts.
- **PreparedCall** (`PreparedCall` type, [src/types.ts](src/types.ts)): the output of `prepareCall`. A built-but-not-fully-signed transaction plus the BIP-143 sighash for external signers, packaged with opaque internals that `finalizeCall` consumes.
- **State**: the mutable Bitcoin Script payload that follows the last `OP_RETURN` in a stateful contract's locking script. Ordered by `StateField.index`. Encoded as raw `OP_NUM2BIN` bytes for ints, single bytes for bools, fixed-size raw bytes for `PubKey`/`Addr`/`Ripemd160`/`Sha256`/`Point`, and length-prefixed push data for variable types.
- **UTXO** (`UTXO` interface, [src/types.ts](src/types.ts)): `{ txid, outputIndex, satoshis, script }`. The contract tracks its current UTXO across deploy → call → call.
- **Inscription** (`Inscription` interface, [src/ordinals/types.ts](src/ordinals/types.ts)): a 1sat ordinals envelope spliced between code and state in the locking script. Immutable across state transitions once deployed.

---

## Writing a contract

Contracts are written in TypeScript (or any of the other Rúnar surface formats: Solidity-like, Move-style, Go DSL, Rust DSL, Python, Java, Ruby, Zig) and saved as `Counter.runar.ts` (etc.). They are compiled to a `RunarArtifact` by `runar-compiler` and then handed to `RunarContract`.

The Quick Start contract:

```typescript
// examples/ts/stateful-counter/Counter.runar.ts
import { StatefulSmartContract, assert } from 'runar-lang';

class Counter extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment() {
    this.count++;
  }

  public decrement() {
    assert(this.count > 0n);
    this.count--;
  }
}
```

For a complete tour of the language (types, builtins, the stateful vs stateless distinction, multi-output methods, OP_PUSH_TX semantics, and the language subset rules) see <https://runar.build>.

---

## Compiling

The SDK consumes compiled artifacts. There are two ways to obtain one.

**In-process (during tests, build scripts, or short pipelines):**

```typescript
import { readFileSync } from 'node:fs';
import { compile } from 'runar-compiler';

const source = readFileSync('Counter.runar.ts', 'utf8');
const result = compile(source, { fileName: 'Counter.runar.ts' });

if (!result.artifact) {
  // result.diagnostics is an array of { message, severity, line?, column? }
  throw new Error(JSON.stringify(result.diagnostics, null, 2));
}

const artifact = result.artifact;
```

`compile` never throws; failures appear in `result.diagnostics` with `severity === 'error'`. The function auto-dispatches by file extension (`.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.java`).

**Ahead-of-time (recommended for production):**

```bash
pnpm add -D runar-cli
pnpm exec runar compile examples/ts/stateful-counter/Counter.runar.ts -o artifacts/
```

That writes `artifacts/Counter.json`, which you load with `JSON.parse(fs.readFileSync(...))` or with a bundler-aware import. Note: when importing JSON directly under bundlers like Vite (`import artifact from './Counter.json'`), `bigint` initial values may arrive as strings; the SDK constructor automatically revives them via the artifact's type metadata.

---

## Deploying contracts

`RunarContract.deploy` creates a transaction whose first output is the contract locking script and broadcasts it via the connected provider.

```typescript
import { RunarContract, WhatsOnChainProvider, LocalSigner } from 'runar-sdk';
import artifact from './artifacts/Counter.json' with { type: 'json' };

const provider = new WhatsOnChainProvider('testnet');
const signer = new LocalSigner(process.env.PRIV_KEY!); // hex or WIF
const counter = new RunarContract(artifact, [0n]);
counter.connect(provider, signer);

const { txid, tx } = await counter.deploy({
  satoshis: 1_000,            // value locked in the contract output (default 1)
  changeAddress: undefined,    // optional; defaults to signer.getAddress()
});

console.log('deploy txid:', txid);
console.log('contract UTXO:', counter.getUtxo());
```

Mechanics:

1. `provider.getUtxos(signer.getAddress())` is queried for funding inputs.
2. `selectUtxos` picks UTXOs largest-first until inputs cover `satoshis + estimatedFee`.
3. `buildDeployTransaction` assembles the transaction with the contract output first and a single P2PKH change output last (only when change is positive).
4. Each input is signed by `signer.sign(...)` against its source script. Unlocking scripts use `<sig> <pubKey>` push data.
5. The transaction is broadcast via `provider.broadcast(tx)`. The returned txid is stored in the contract's tracked UTXO so the next call resolves it without further lookups.
6. The contract's `currentUtxo` is set to `{ txid, outputIndex: 0, satoshis, script: lockingScript }`.

If `provider.getUtxos` returns no UTXOs the function throws `RunarContract.deploy: no UTXOs found for address <addr>`.

You can also pass provider and signer explicitly: `counter.deploy(provider, signer, { satoshis: 1000 })`.

For BRC-100 wallets, use `deployWithWallet` instead; see [9c](#9c-brc-100-wallet-signing).

---

## Calling contract methods

A call spends the contract UTXO. There are three signing flows.

### 9a. Single-signer (`call`)

```typescript
const { txid } = await counter.call('increment', []);
console.log('new count:', counter.state.count);
```

What happens, step by step:

1. `prepareCall` builds the transaction with placeholder signatures and the OP_PUSH_TX preimage.
2. The connected `signer.sign(...)` is invoked once per `Sig` parameter (the SDK auto-detects them by ABI type).
3. `finalizeCall` swaps the placeholders for real signatures, replaces the primary unlocking script, and broadcasts.
4. The contract's tracked UTXO is updated to point at the new continuation output (or cleared, for terminal methods).

For stateful contracts that don't take any user-provided arguments — like `Counter` — pass an empty `args` array. The SDK auto-injects the `SigHashPreimage`, `_changePKH`, `_changeAmount`, and `_newAmount` parameters that the compiler added at the contract's method boundary.

`CallOptions` covers everything else:

```typescript
import { type CallOptions } from 'runar-sdk';

await counter.call('increment', [], {
  satoshis: 1_000,                              // value for the continuation output
  changeAddress: '1MyChange...',                // override change address
  changePubKey: '03abcd...',                    // override pubkey used for change PKH
  newState: { count: 5n },                      // explicit state override (skips ANF auto-compute)
});
```

When `newState` is omitted, the SDK runs the ANF interpreter against the contract's IR and the method arguments to derive the new state, then writes it into the continuation output. This matches what the on-chain script will compute, so the `OP_HASH256(outputs)` check in `checkPreimage` succeeds. If you pass `newState` with an incorrect value, the broadcast will be rejected by the network — that's how `TestCounter_WrongStateHash_Rejected` in `integration/go/counter_test.go` validates the on-chain enforcement.

You can also pass `provider` and `signer` positionally: `counter.call('increment', [], provider, signer, options?)`.

### 9b. Multi-signer (`prepareCall` / `finalizeCall`)

For hardware-wallet signing, multi-party signing, deferred signing, or any flow where the private key is not in the calling process, split the call in two:

```typescript
import { RunarContract } from 'runar-sdk';
import type { PreparedCall } from 'runar-sdk';

// 1. Build the transaction without signing the primary contract input.
//    Pass null for any Sig parameter you want left as a placeholder.
const prepared: PreparedCall = await contract.prepareCall(
  'transfer',
  [null /* sig */, recipientAddress, 500n /* amount */],
  { changeAddress: myAddress },
);

// 2. Hand `prepared.sighash` (and/or `prepared.tx`) to your external signer.
//    The sighash is the BIP-143 digest the wallet must ECDSA-sign.
const sigHex: string = await externalSign(prepared.sighash, prepared.tx);

// 3. Inject the signature back. The map keys are the user-visible arg
//    indices listed in `prepared.sigIndices`.
const signatures: Record<number, string> = {
  [prepared.sigIndices[0]!]: sigHex,
};

// 4. Finalize: swap placeholders, broadcast, update tracked UTXO.
const { txid } = await contract.finalizeCall(prepared, signatures);
```

`prepareCall` already signs P2PKH funding inputs and any additional contract inputs (when `additionalContractInputs` is set). It only leaves the primary contract input's `Sig` parameters as 72-byte placeholders for the external signer.

`prepared.sighash` is `SHA256(prepared.preimage)` — the inner SHA-256 of the BIP-143 double-hash. Most wallets expect the unhashed sighash; `WalletSigner.signHash` accepts it directly. If your signer expects the raw preimage (to recompute and verify the sighash itself), use `prepared.preimage`.

For complete examples, see `packages/runar-sdk/src/__tests__/external-signer.test.ts`.

### 9c. BRC-100 wallet signing

For browser- and extension-resident wallets that own their own keys (BRC-100 `WalletClient`), use `WalletProvider` together with `WalletSigner`:

```typescript
import {
  RunarContract,
  WalletProvider,
  WalletSigner,
} from 'runar-sdk';
import { WalletClient } from '@bsv/sdk';

const wallet = new WalletClient();
const signer = new WalletSigner({
  wallet,
  protocolID: [2, 'my counter app'],   // BRC-100 protocol ID
  keyID: '1',
});
const provider = new WalletProvider({
  wallet,
  signer,
  basket: 'my-counter',                // wallet basket holding funding UTXOs
  fundingTag: 'funding',               // tag identifying funding outputs (default 'funding')
  arcUrl: 'https://arc.gorillapool.io', // ARC broadcast endpoint
  network: 'mainnet',
});

// Make sure the wallet basket has enough funding for deploy + a few calls:
await provider.ensureFunding(10_000);

const counter = new RunarContract(artifact, [0n]);
counter.connect(provider, signer);

// deployWithWallet routes the deploy transaction through `wallet.createAction`,
// so the wallet displays a permission prompt and signs internally.
const { txid, outputIndex } = await counter.deployWithWallet({
  satoshis: 1_000,
  description: 'Deploy Counter',
});

// Subsequent calls go through the normal call() path; WalletSigner handles
// signing internally via wallet.createSignature.
await counter.call('increment', []);
```

`WalletProvider` broadcasts in EF (Extended Format) via ARC, caching parent transactions for child-tx EF assembly. If you also pass `overlayUrl` and `overlayTopics`, every broadcast is fire-and-forget submitted to the overlay for indexing.

---

## Stateful contracts

A stateful contract extends `StatefulSmartContract` in source. The compiler emits `OP_CODESEPARATOR` boundaries, an auto-injected `checkPreimage` at every method entry, and a continuation output check on exit. The SDK is responsible for actually constructing matching outputs and the BIP-143 OP_PUSH_TX preimage at runtime.

### State chaining

The locking script is laid out as `<code> [<inscription envelope>] OP_RETURN <state>`. State is read from the *last* `OP_RETURN` at a real opcode boundary (not from inside push data), which is what `findLastOpReturn` walks for.

The SDK tracks the contract's current UTXO across the lifecycle:

```typescript
const counter = new RunarContract(artifact, [0n]);
counter.connect(provider, signer);

await counter.deploy({ satoshis: 1_000 });
console.log(counter.getUtxo()?.txid);   // deploy txid, vout 0

await counter.call('increment', []);
console.log(counter.getUtxo()?.txid);   // call txid, vout 0
console.log(counter.state.count);       // 1n

await counter.call('increment', []);
console.log(counter.state.count);       // 2n

// Terminal methods (those not producing a continuation output) clear the UTXO:
await counter.call('finish', []);       // hypothetical terminal method
console.log(counter.getUtxo());         // null
```

To reconnect to an existing on-chain contract:

```typescript
// If you have the txid (or just want the SDK to fetch the tx itself):
const counter = await RunarContract.fromTxId(artifact, txid, 0, provider);

// If you already know the UTXO (e.g. from an overlay service):
const counter = RunarContract.fromUtxo(artifact, {
  txid,
  outputIndex: 0,
  satoshis: 1_000,
  script: lockingScriptHex,
});

console.log(counter.state.count); // decoded from the on-chain script
```

`fromUtxo` is synchronous; `fromTxId` only adds the provider round-trip to fetch the transaction.

### OP_PUSH_TX

The OP_PUSH_TX pattern lets a script verify the transaction it's part of without OP_CHECKSIGVERIFY of an external signature. The SDK uses private key `k = 1` (public key = generator point `G`), computes the BIP-143 preimage that the on-chain script will rebuild, signs the preimage with low-S enforcement, and pushes both onto the unlocking stack as `<opPushTxSig> <preimage>`. The on-chain `checkPreimage` opcode recomputes the preimage from the spending tx and verifies it against the signature.

`computeOpPushTx(tx, inputIndex, subscript, satoshis, codeSeparatorIndex?)` is exported for advanced use; you almost never need to call it manually because `RunarContract.call` invokes it as part of `prepareCall`. The `codeSeparatorIndex` argument is required for stateful contracts because the BIP-143 `scriptCode` for the OP_PUSH_TX sig must start *after* the contract's `OP_CODESEPARATOR`.

### ANF auto state

When you call a stateful method without supplying `newState`, the SDK runs `computeNewStateAndDataOutputs(artifact.anf, methodName, currentState, args, ctorArgs)` against the contract's compiled ANF IR. This walks the same logic the script executes on chain, computes the resulting state, and (for methods that use `this.addDataOutput(...)`) emits matching data outputs in declaration order. The result is a continuation output whose `OP_HASH256` matches what the script will compute.

If you supply `newState` explicitly, the SDK trusts you. If your value is wrong, the on-chain script rejects the transaction and `provider.broadcast(...)` throws.

---

## UTXO and fee management

`Provider.getUtxos(address)` returns spendable P2PKH UTXOs for the funding address. `selectUtxos(utxos, target, scriptByteLen, feeRate)` ([src/deployment.ts](src/deployment.ts)) picks the smallest set of inputs (largest-first) such that `total >= target + estimatedFee`. If the total is insufficient, the selector returns everything it has and `buildDeployTransaction` throws `insufficient funds. Need <X> sats, have <Y>`.

Fees are computed from actual script sizes (not hardcoded P2PKH assumptions):

```typescript
import { estimateDeployFee, estimateCallFee } from 'runar-sdk';

const deployFee = estimateDeployFee(
  numInputs,           // count of P2PKH inputs
  lockingScriptByteLen,
  100,                 // fee rate in sat/KB (default 100 = 0.1 sat/byte)
);

const callFee = estimateCallFee(
  newLockingScriptByteLen,  // continuation output script size
  unlockingScriptByteLen,   // primary contract input unlocking script size
  numFundingInputs,
  100,
);
```

The default fee rate is 100 sat/KB (0.1 sat/byte) — BSV's standard relay fee. `Provider.getFeeRate()` returns the actual rate the SDK will use; `MockProvider.setFeeRate(rate)` overrides it for tests.

Change outputs are added to the transaction only when the change is positive. The default change address is the signer's address; override with `changeAddress` in `DeployOptions` or `CallOptions`. To override the public key used to derive the change PKH (relevant for stateful contracts whose methods read `_changePKH`), pass `changePubKey`.

---

## Typed contract bindings

The `runar-sdk/codegen` subpath (separate package export) generates a typed wrapper class around `RunarContract`. The generated class exposes one async method per public contract method, with TypeScript-typed parameters, hides auto-computed parameters (`Sig`, `SigHashPreimage`, `_changePKH`, `_changeAmount`, `_newAmount`), and distinguishes terminal from state-mutating methods.

CLI:

```bash
pnpm exec runar codegen artifacts/Counter.json -o src/generated/ --lang ts
```

Programmatic:

```typescript
import { generateTypescript } from 'runar-sdk/codegen';
import artifact from './artifacts/Counter.json' with { type: 'json' };

const wrapperSource: string = generateTypescript(artifact);
// Write wrapperSource to a .ts file and import it like a normal module.
```

Generated wrapper for `Counter` (abridged):

```typescript
import { RunarContract, buildP2PKHScript } from 'runar-sdk';
import type { Provider, Signer, TransactionData, DeployOptions, RunarArtifact } from 'runar-sdk';

type CallResult = { txid: string; tx: TransactionData };

export interface CounterStatefulCallOptions {
  satoshis?: number;
  changeAddress?: string;
  changePubKey?: string;
  newState?: Record<string, unknown>;
  outputs?: Array<{ satoshis: number; state: Record<string, unknown> }>;
}

export class CounterContract {
  private readonly inner: RunarContract;

  constructor(artifact: RunarArtifact, args: { count: bigint }) {
    this.inner = new RunarContract(artifact, [args.count]);
  }

  static fromUtxo(artifact: RunarArtifact, utxo: {...}): CounterContract { /* ... */ }
  static async fromTxId(artifact: RunarArtifact, txid: string, vout: number, p: Provider): Promise<CounterContract> { /* ... */ }

  connect(provider: Provider, signer: Signer): void { this.inner.connect(provider, signer); }

  async deploy(options?: DeployOptions): Promise<CallResult>;
  async deploy(provider: Provider, signer: Signer, options?: DeployOptions): Promise<CallResult>;
  async deploy(...args: unknown[]): Promise<CallResult> { return (this.inner.deploy as Function)(...args); }

  /** State-mutating method: increment */
  async increment(options?: CounterStatefulCallOptions): Promise<CallResult> {
    return this.inner.call('increment', [], options);
  }

  /** State-mutating method: decrement */
  async decrement(options?: CounterStatefulCallOptions): Promise<CallResult> {
    return this.inner.call('decrement', [], options);
  }

  get contract(): RunarContract { return this.inner; }
}
```

Usage:

```typescript
import artifact from './artifacts/Counter.json' with { type: 'json' };
import { CounterContract } from './generated/Counter.js';

const counter = new CounterContract(artifact, { count: 0n });
counter.connect(provider, signer);

await counter.deploy({ satoshis: 1_000 });
await counter.increment();
await counter.increment();
console.log(counter.contract.state.count); // 2n
```

For methods with `Sig` parameters, the generator also emits a `prepareXxx` / `finalizeXxx` pair with the same hidden-parameter handling, so the multi-signer flow stays type-safe.

The codegen subpath also exports cross-target generators: `generateGo`, `generateRust`, `generatePython`, `generateZig` — useful when one repository owns the contract and ships typed bindings to consumers in different languages.

---

## Testing

Two layers, depending on what you're verifying.

### 13a. Off-chain runtime simulation

`runar-testing` ships a `TestContract` API that runs the contract through Rúnar's reference interpreter (not the script VM). Crypto is mocked: `checkSig` always returns true, `checkPreimage` always returns true, mock signatures and pubkeys are deterministic placeholders. This is the right tool for unit-testing business logic without dealing with transactions.

```typescript
import { describe, it, expect } from 'vitest';
import { TestContract } from 'runar-testing';
import { readFileSync } from 'node:fs';

describe('Counter', () => {
  const source = readFileSync('Counter.runar.ts', 'utf8');

  it('increments', () => {
    const counter = TestContract.fromSource(source, { count: 0n });
    counter.call('increment');
    expect(counter.state.count).toBe(1n);
  });

  it('rejects decrement from zero', () => {
    const counter = TestContract.fromSource(source, { count: 0n });
    const result = counter.call('decrement');
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/assert/i);
  });
});
```

`TestContract` is the right choice for "does my contract logic produce the expected state given these inputs?". It will not catch BIP-143-related bugs or OP_CODESEPARATOR mistakes — those need an integration test (next section) or the conformance suite.

### 13b. Integration testing against a regtest node

For end-to-end tests that exercise actual signing, broadcasting, and on-chain script execution, run a Bitcoin SV regtest node and use `RPCProvider`. The repository's `integration/ts/` suite shows the canonical pattern.

```typescript
// integration/ts/counter.test.ts (excerpted)
import { describe, it, expect } from 'vitest';
import { RunarContract } from 'runar-sdk';
import { compileContract } from './helpers/compile.js';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('Counter', () => {
  it('chains 0 -> 1 -> 2', async () => {
    const artifact = compileContract('examples/ts/stateful-counter/Counter.runar.ts');
    const contract = new RunarContract(artifact, [0n]);

    const provider = createProvider(); // RPCProvider with autoMine: true
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, {});

    await contract.call('increment', [], provider, signer);
    expect(contract.state.count).toBe(1n);

    await contract.call('increment', [], provider, signer);
    expect(contract.state.count).toBe(2n);
  });
});
```

`createProvider`, `createFundedWallet`, and the regtest helpers live in `integration/ts/helpers/` and are reusable in your own integration suite.

For cross-SDK byte-identity verification (proving the TypeScript SDK produces the same locking script as the Go, Rust, Python, Zig, Ruby, and Java SDKs for the same artifact + constructor args), the `conformance/sdk-output/` suite drives all seven SDKs against shared fixtures including `stateful-counter`.

---

## Provider configuration

### MockProvider

Pure in-memory provider for unit tests. No network access.

```typescript
import { MockProvider } from 'runar-sdk';

const provider = new MockProvider('testnet'); // 'mainnet' | 'testnet', default 'testnet'

provider.addUtxo('1MyAddress...', {
  txid: 'aa'.repeat(32),
  outputIndex: 0,
  satoshis: 100_000,
  script: '76a914...88ac',
});

provider.addTransaction({
  txid: 'aa'.repeat(32),
  version: 1,
  inputs: [],
  outputs: [{ satoshis: 100_000, script: '76a914...88ac' }],
  locktime: 0,
});

provider.setFeeRate(100); // sat/KB

// After broadcasts, inspect what was sent:
console.log(provider.getBroadcastedTxs());        // raw hex strings
console.log(provider.getBroadcastedTxObjects());  // @bsv/sdk Transaction objects
```

`broadcast` returns a deterministic fake txid and stores the raw hex against it (so `getRawTransaction(txid)` works), but does *not* register a `TransactionData` entry. If a downstream call needs `getTransaction(txid)` to succeed, call `provider.addTransaction(...)` first.

### RPCProvider

Talks to a Bitcoin SV node over JSON-RPC. Suitable for regtest and self-hosted nodes.

```typescript
import { RPCProvider } from 'runar-sdk';

const provider = new RPCProvider(
  'http://localhost:18332',
  'bitcoin', 'bitcoin',
  {
    network: 'testnet',     // default 'testnet'
    autoMine: true,          // call generate(toaddress) after each broadcast (default false)
    mineAddress: '',         // when set, uses generatetoaddress; otherwise generate
  },
);
```

`getContractUtxo()` always returns `null` on `RPCProvider`. Track the contract UTXO via `RunarContract.getUtxo()` instead, or use an indexer-backed provider.

### WhatsOnChainProvider

HTTP client for the WhatsOnChain BSV API.

```typescript
import { WhatsOnChainProvider } from 'runar-sdk';

const provider = new WhatsOnChainProvider('mainnet'); // 'mainnet' | 'testnet'
```

WoC's UTXO endpoint does not return locking scripts, so `getUtxos` populates `script: ''`. If you need the script, fetch the source transaction with `getTransaction(txid)` and read it from the `outputs[outputIndex]`.

### GorillaPoolProvider

HTTP client for GorillaPool's 1sat ordinals API. Implements the standard `Provider` interface plus ordinals-specific methods.

```typescript
import { GorillaPoolProvider } from 'runar-sdk';

const provider = new GorillaPoolProvider('mainnet');

// Standard Provider interface
const utxos = await provider.getUtxos('1MyAddress...');

// Ordinals-specific helpers
const inscriptions = await provider.getInscriptionsByAddress('1MyAddress...');
const detail = await provider.getInscription(`${txid}_${vout}`);
const balance = await provider.getBSV20Balance('1MyAddress...', 'RUNAR');
const tokens = await provider.getBSV20Utxos('1MyAddress...', 'RUNAR');

// BSV-21 (ID-based)
const bsv21Balance = await provider.getBSV21Balance('1MyAddress...', `${txid}_${vout}`);
const bsv21Utxos = await provider.getBSV21Utxos('1MyAddress...', `${txid}_${vout}`);
```

### WalletProvider

Backs BRC-100 wallets. See [9c](#9c-brc-100-wallet-signing) for full setup.

### Custom providers

Implement the `Provider` interface to wrap any backend (overlay services, custom indexers, internal RPC):

```typescript
import type { Provider, UTXO, TransactionData } from 'runar-sdk';
import type { Transaction } from '@bsv/sdk';

class MyProvider implements Provider {
  async getTransaction(txid: string): Promise<TransactionData> { /* ... */ }
  async broadcast(tx: Transaction): Promise<string> { /* ... */ }
  async getUtxos(address: string): Promise<UTXO[]> { /* ... */ }
  async getContractUtxo(scriptHash: string): Promise<UTXO | null> { /* ... */ }
  getNetwork(): 'mainnet' | 'testnet' { return 'mainnet'; }
  async getFeeRate(): Promise<number> { return 100; }
  async getRawTransaction(txid: string): Promise<string> { /* ... */ }
}
```

---

## Full API reference

Symbols are listed alphabetically within each subsection. All paths in the headings are relative to `packages/runar-sdk/`.

### Contract runtime

#### `RunarContract` ([src/contract.ts](src/contract.ts))

Runtime wrapper around a compiled artifact.

##### `new RunarContract(artifact, constructorArgs)`

```typescript
constructor(artifact: RunarArtifact, constructorArgs: unknown[])
```

- `artifact`: a `RunarArtifact` (re-exported from `runar-ir-schema`).
- `constructorArgs`: positional values matching `artifact.abi.constructor.params` in order. Use `bigint` for `bigint`/`int`, `boolean` for `bool`, hex strings for `ByteString`/`PubKey`/`Addr`/`Ripemd160`/`Sha256`/`Point`, JS arrays for `FixedArray<T, N>`.

Throws `Error` if `constructorArgs.length` doesn't match the ABI.

##### `contract.connect(provider, signer)`

```typescript
connect(provider: Provider, signer: Signer): void
```

Stores the provider and signer so subsequent `deploy()` and `call()` invocations can omit them.

##### `contract.deploy(options)` / `contract.deploy(provider, signer, options)`

```typescript
deploy(options: DeployOptions): Promise<{ txid: string; tx: TransactionData }>
deploy(provider: Provider, signer: Signer, options: DeployOptions): Promise<{ txid: string; tx: TransactionData }>
```

Builds a deploy transaction, signs all P2PKH inputs, broadcasts, and updates `currentUtxo`. Throws when no funding UTXOs are available. Errors from the network propagate from `provider.broadcast`.

##### `contract.deployWithWallet(options)`

```typescript
deployWithWallet(options?: { satoshis?: number; description?: string }): Promise<{ txid: string; outputIndex: number }>
```

BRC-100 path. Requires the connected provider to be a `WalletProvider`. Calls `wallet.createAction(...)` so the wallet itself signs the deploy transaction. Throws `'deployWithWallet requires a connected WalletProvider...'` otherwise.

##### `contract.call(methodName, args, options?)` / `contract.call(methodName, args, provider, signer, options?)`

```typescript
call(methodName: string, args: unknown[], options?: CallOptions): Promise<{ txid: string; tx: TransactionData }>
call(methodName: string, args: unknown[], provider: Provider, signer: Signer, options?: CallOptions): Promise<{ txid: string; tx: TransactionData }>
```

Spends the contract UTXO. For stateful contracts, creates a continuation output with the new state (auto-computed from the ANF IR if `options.newState` is omitted). Updates `currentUtxo` to the new output, or sets it to `null` for terminal methods.

Throws when the contract isn't deployed (`'contract is not deployed. Call deploy() or fromTxId() first.'`), when the method isn't found, or when arg count is wrong. Network errors propagate.

##### `contract.prepareCall(methodName, args, options?)`

```typescript
prepareCall(methodName: string, args: unknown[], options?: CallOptions): Promise<PreparedCall>
```

Multi-signer flow. See [9b](#9b-multi-signer-preparecall--finalizecall). Pass `null` for any `Sig` parameter you want left unsigned. The returned `PreparedCall` contains:

- `sighash` (hex): BIP-143 sighash for external signers.
- `preimage` (hex): full preimage if you need to re-derive the sighash.
- `opPushTxSig` (hex): OP_PUSH_TX DER signature + sighash byte. Empty when not needed.
- `tx`: `@bsv/sdk` `Transaction` with funding inputs already signed.
- `sigIndices`: argument indices that need external signatures.
- Opaque internal fields (prefixed `_`) consumed by `finalizeCall`.

##### `contract.finalizeCall(prepared, signatures)`

```typescript
finalizeCall(prepared: PreparedCall, signatures: Record<number, string>): Promise<{ txid: string; tx: TransactionData }>
```

Injects external signatures into the placeholders, broadcasts, and updates `currentUtxo`. `signatures` keys are arg indices (use `prepared.sigIndices`); values are DER signature hex strings with the sighash byte appended.

##### `contract.state` (getter)

```typescript
get state(): Record<string, unknown>
```

Returns a shallow copy of the current state. `bigint` values stay as `bigint`; `bool` as `boolean`; byte types as hex strings; `FixedArray<T, N>` as JS arrays.

##### `contract.setState(newState)`

```typescript
setState(newState: Record<string, unknown>): void
```

Merges `newState` into the tracked state. Useful for tests; in production prefer letting `call()` compute the next state from the ANF IR.

##### `contract.getLockingScript()`

```typescript
getLockingScript(): string
```

Returns the full locking script hex for the current state (code + optional inscription envelope + `OP_RETURN` + serialized state for stateful contracts). Used internally by `deploy()` and `call()`.

##### `contract.buildUnlockingScript(methodName, args)`

```typescript
buildUnlockingScript(methodName: string, args: unknown[]): string
```

Returns the unlocking script hex for `methodName` with the given (already-resolved) args. For multi-method contracts a method-selector script number is appended automatically. This is a low-level helper; `call()` and `prepareCall()` use it internally.

##### `contract.getUtxo()`

```typescript
getUtxo(): UTXO | null
```

Returns the contract's current UTXO, or `null` if the contract has not been deployed or has been spent by a terminal method.

##### `contract.withInscription(inscription)`

```typescript
withInscription(inscription: Inscription): this
```

Attaches a 1sat ordinals envelope to the contract. The envelope is spliced into the locking script between the compiled code and the state section, and persists identically across all state transitions.

##### `contract.inscription` (getter)

```typescript
get inscription(): Inscription | null
```

Returns the attached inscription, or `null`.

##### `RunarContract.fromUtxo(artifact, utxo)`

```typescript
static fromUtxo(
  artifact: RunarArtifact,
  utxo: { txid: string; outputIndex: number; satoshis: number; script: string },
): RunarContract
```

Synchronously reconstructs a contract from a known UTXO. Decodes the state from the locking script. Detects and re-attaches any 1sat inscription envelope.

##### `RunarContract.fromTxId(artifact, txid, outputIndex, provider)`

```typescript
static fromTxId(
  artifact: RunarArtifact,
  txid: string,
  outputIndex: number,
  provider: Provider,
): Promise<RunarContract>
```

Like `fromUtxo`, but fetches the transaction via the provider first. Throws when `outputIndex >= tx.outputs.length`.

### Providers

#### `Provider` interface ([src/providers/provider.ts](src/providers/provider.ts))

```typescript
interface Provider {
  getTransaction(txid: string): Promise<TransactionData>;
  broadcast(tx: Transaction): Promise<string>;
  getUtxos(address: string): Promise<UTXO[]>;
  getContractUtxo(scriptHash: string): Promise<UTXO | null>;
  getNetwork(): 'mainnet' | 'testnet';
  getFeeRate(): Promise<number>; // satoshis per KB
  getRawTransaction(txid: string): Promise<string>;
}
```

#### `MockProvider` ([src/providers/mock.ts](src/providers/mock.ts))

```typescript
new MockProvider(network?: 'mainnet' | 'testnet') // default 'testnet'

addTransaction(tx: TransactionData): void
addUtxo(address: string, utxo: UTXO): void
addContractUtxo(scriptHash: string, utxo: UTXO): void
setFeeRate(rate: number): void                       // default 100 sat/KB

getBroadcastedTxs(): readonly string[]              // raw hex strings
getBroadcastedTxObjects(): readonly Transaction[]
```

`broadcast()` returns a deterministic fake txid (FNV-style hash of the raw hex) and stores the raw hex but does not register a `TransactionData` entry. Pre-register with `addTransaction()` if downstream `getTransaction(txid)` calls are expected.

#### `RPCProvider` ([src/providers/rpc-provider.ts](src/providers/rpc-provider.ts))

```typescript
new RPCProvider(url: string, user: string, pass: string, options?: RPCProviderOptions)

interface RPCProviderOptions {
  autoMine?: boolean;             // default false
  mineAddress?: string;            // default '' (uses 'generate' RPC)
  network?: 'mainnet' | 'testnet'; // default 'testnet'
}
```

Issues JSON-RPC calls (`getrawtransaction`, `sendrawtransaction`, `listunspent`, `generate(toaddress)`). 10-minute timeout per request. `getContractUtxo` always returns `null`.

#### `WhatsOnChainProvider` ([src/providers/woc.ts](src/providers/woc.ts))

```typescript
new WhatsOnChainProvider(network?: 'mainnet' | 'testnet') // default 'mainnet'
```

UTXO entries returned by `getUtxos()` have empty `script` strings (WoC API limitation). `getFeeRate()` returns the BSV standard 100 sat/KB.

#### `GorillaPoolProvider` ([src/providers/gorillapool.ts](src/providers/gorillapool.ts))

```typescript
new GorillaPoolProvider(network?: 'mainnet' | 'testnet') // default 'mainnet'

// Standard Provider methods plus:
getInscriptionsByAddress(address: string): Promise<InscriptionInfo[]>
getInscription(inscriptionId: string): Promise<InscriptionDetail>           // id format: <txid>_<vout>
getBSV20Balance(address: string, tick: string): Promise<string>
getBSV20Utxos(address: string, tick: string): Promise<UTXO[]>
getBSV21Balance(address: string, id: string): Promise<string>               // id format: <txid>_<vout>
getBSV21Utxos(address: string, id: string): Promise<UTXO[]>
```

#### `WalletProvider` ([src/providers/wallet-provider.ts](src/providers/wallet-provider.ts))

```typescript
new WalletProvider(options: WalletProviderOptions)

interface WalletProviderOptions {
  wallet: WalletClient;            // BRC-100 client (from @bsv/sdk)
  signer: Signer;                   // typically a WalletSigner backed by the same wallet
  basket: string;                   // wallet basket holding funding outputs
  fundingTag?: string;              // default 'funding'
  arcUrl?: string;                  // default 'https://arc.gorillapool.io'
  overlayUrl?: string;              // optional overlay service for tx submission
  overlayTopics?: string[];         // overlay topics, e.g. ['tm_myapp']
  network?: 'mainnet' | 'testnet'; // default 'mainnet'
  feeRate?: number;                 // default 100 sat/KB
}

// Extra methods beyond the Provider interface:
ensureFunding(minSatoshis: number): Promise<void>
cacheTx(txid: string, rawHex: string): void
```

`broadcast()` sends EF-format transactions to ARC and (if configured) submits to the overlay for indexing.

### Signers

#### `Signer` interface ([src/signers/signer.ts](src/signers/signer.ts))

```typescript
interface Signer {
  getPublicKey(): Promise<string>;            // hex-encoded compressed key (66 chars)
  getAddress(): Promise<string>;              // Base58Check P2PKH address
  sign(
    txHex: string,
    inputIndex: number,
    subscript: string,
    satoshis: number,
    sigHashType?: number,                      // default 0x41 = SIGHASH_ALL | SIGHASH_FORKID
  ): Promise<string>;                          // DER signature hex + sighash byte
}
```

#### `LocalSigner` ([src/signers/local.ts](src/signers/local.ts))

```typescript
new LocalSigner(keyInput: string)

getPrivateKeyHex(): string
```

Accepts a 64-char hex private key or a WIF (Base58Check) key starting with 5/K/L. Wraps `@bsv/sdk`'s `PrivateKey`, `TransactionSignature`, and `Hash` for real secp256k1 ECDSA signing with BIP-143 sighash. Throws on malformed keys.

The TypeScript SDK does **not** ship a separate `MockSigner` class. Tests construct a `LocalSigner` from a hardcoded test key (the canonical choice is `'00...01'`, the smallest valid secp256k1 private key) — see `packages/runar-sdk/src/__tests__/contract-lifecycle.test.ts`. This intentionally diverges from the Go/Rust/Python/Zig/Ruby/Java SDKs which have a `MockSigner` class.

#### `ExternalSigner` ([src/signers/external.ts](src/signers/external.ts))

```typescript
new ExternalSigner(pubKeyHex: string, addressStr: string, signFn: SignCallback)

type SignCallback = (
  txHex: string,
  inputIndex: number,
  subscript: string,
  satoshis: number,
  sigHashType?: number,
) => Promise<string>;
```

Delegates signing to a callback. Useful for hardware wallets, browser-extension wallets, or any out-of-process signer. The callback receives the same arguments as `Signer.sign` and must return DER signature hex + sighash byte.

#### `WalletSigner` ([src/signers/wallet.ts](src/signers/wallet.ts))

```typescript
new WalletSigner(options: WalletSignerOptions)

interface WalletSignerOptions {
  protocolID: [SecurityLevel, string]; // BRC-100 protocol identifier
  keyID: string;                        // BRC-100 key derivation identifier
  wallet?: WalletClient;                // optional pre-existing client
}

signHash(sighash: string | number[]): Promise<string>  // DER signature hex (no sighash byte)
```

Computes the BIP-143 sighash locally, then delegates ECDSA signing to the BRC-100 wallet via `wallet.createSignature({ hashToDirectlySign, ... })`. Caches the public key after the first `getPublicKey()` call.

### Transaction building

#### `buildDeployTransaction` ([src/deployment.ts](src/deployment.ts))

```typescript
buildDeployTransaction(
  lockingScript: string,
  utxos: UTXO[],
  satoshis: number,
  changeAddress: string,
  changeScript: string,
  feeRate?: number,                  // default 100 sat/KB
): { tx: Transaction; inputCount: number }
```

Builds an unsigned deploy transaction (P2PKH inputs, contract output first, optional change output). Throws when `utxos` is empty or when funds are insufficient.

#### `buildCallTransaction` ([src/calling.ts](src/calling.ts))

```typescript
buildCallTransaction(
  currentUtxo: UTXO,
  unlockingScript: string,
  newLockingScript?: string,
  newSatoshis?: number,
  changeAddress?: string,
  changeScript?: string,
  additionalUtxos?: UTXO[],
  feeRate?: number,                                  // default 100 sat/KB
  options?: {
    contractOutputs?: Array<{ script: string; satoshis: number }>;
    additionalContractInputs?: Array<{ utxo: UTXO; unlockingScript: string }>;
    dataOutputs?: Array<{ script: string; satoshis: number }>;
  },
): { tx: Transaction; inputCount: number; changeAmount: number }
```

Builds a method-call transaction. The primary contract input uses the supplied `unlockingScript`. Additional contract inputs come pre-signed; P2PKH funding inputs come unsigned. Output ordering is: contract outputs (or single continuation), data outputs, change.

#### `selectUtxos` ([src/deployment.ts](src/deployment.ts))

```typescript
selectUtxos(
  utxos: UTXO[],
  targetSatoshis: number,
  lockingScriptByteLen: number,
  feeRate?: number,                  // default 100
): UTXO[]
```

Largest-first UTXO selection, fee-aware. Returns the smallest sufficient subset; if the total is still short, returns everything.

#### `estimateDeployFee` ([src/deployment.ts](src/deployment.ts))

```typescript
estimateDeployFee(numInputs: number, lockingScriptByteLen: number, feeRate?: number): number
```

#### `estimateCallFee` ([src/calling.ts](src/calling.ts))

```typescript
estimateCallFee(
  lockingScriptByteLen: number,
  unlockingScriptByteLen: number,
  numFundingInputs: number,
  feeRate?: number,
): number
```

### State

#### `serializeState` ([src/state.ts](src/state.ts))

```typescript
serializeState(fields: StateField[], values: Record<string, unknown>): string
```

Serializes a state record into the hex-encoded payload that follows `OP_RETURN`. Order is determined by `field.index`. `bigint` is encoded as 8-byte little-endian sign-magnitude (`OP_NUM2BIN`-style), `bool` as a single 0x00/0x01 byte, `PubKey`/`Addr`/`Ripemd160`/`Sha256`/`Point` as fixed-size raw bytes, other types as length-prefixed push data.

#### `deserializeState` ([src/state.ts](src/state.ts))

```typescript
deserializeState(fields: StateField[], scriptHex: string): Record<string, unknown>
```

Inverse of `serializeState`. The caller must strip the code prefix and `OP_RETURN` byte first; `extractStateFromScript` does that for you.

#### `extractStateFromScript` ([src/state.ts](src/state.ts))

```typescript
extractStateFromScript(artifact: RunarArtifact, scriptHex: string): Record<string, unknown> | null
```

Walks the script to find the last `OP_RETURN` at an opcode boundary, then deserializes the suffix. Returns `null` for stateless artifacts or scripts with no recognizable state section.

#### `findLastOpReturn` ([src/state.ts](src/state.ts))

```typescript
findLastOpReturn(scriptHex: string): number
```

Returns the hex-char offset of the last `OP_RETURN` (0x6a) at a real opcode boundary, or -1 if none. Walks push data (direct push, OP_PUSHDATA1/2/4) so it won't false-match 0x6a bytes inside push payloads.

### OP_PUSH_TX

#### `computeOpPushTx` ([src/oppushtx.ts](src/oppushtx.ts))

```typescript
computeOpPushTx(
  txOrHex: Transaction | string,
  inputIndex: number,
  subscript: string,
  satoshis: number,
  codeSeparatorIndex?: number,
): { sigHex: string; preimageHex: string }
```

Computes the OP_PUSH_TX DER signature (with low-S enforcement) and BIP-143 preimage for a contract input. `codeSeparatorIndex` is the byte offset of `OP_CODESEPARATOR` in the locking script; pass it for stateful contracts so the BIP-143 `scriptCode` is restricted to the script suffix after the separator.

### Script utilities

#### `buildP2PKHScript` ([src/script-utils.ts](src/script-utils.ts))

```typescript
buildP2PKHScript(addressOrPubKey: string): string
```

Produces a P2PKH locking script. Accepts:
- 40-char hex (raw 20-byte pubkey hash);
- 66-char hex (compressed public key, hashed via `hash160`);
- 130-char hex (uncompressed public key, hashed via `hash160`);
- otherwise treated as Base58Check address.

#### `extractConstructorArgs` ([src/script-utils.ts](src/script-utils.ts))

```typescript
extractConstructorArgs(artifact: RunarArtifact, scriptHex: string): Record<string, unknown>
```

Reads the constructor arg values back out of an on-chain script using `artifact.constructorSlots`. Useful when you discover a UTXO and want to know what its constructor args were.

#### `matchesArtifact` ([src/script-utils.ts](src/script-utils.ts))

```typescript
matchesArtifact(artifact: RunarArtifact, scriptHex: string): boolean
```

Checks whether `scriptHex` was produced from `artifact` (regardless of the constructor args used).

### Tokens

#### `TokenWallet` ([src/tokens.ts](src/tokens.ts))

```typescript
new TokenWallet(artifact: RunarArtifact, provider: Provider, signer: Signer)

getBalance(): Promise<bigint>
transfer(recipientAddr: string, amount: bigint): Promise<string>
merge(): Promise<string>
getUtxos(): Promise<UTXO[]>
```

Convenience wrapper for fungible-token contracts that expose `transfer(sig, to)` and `merge(sig, otherSupply, otherHolder)` methods and a `supply` / `balance` / `amount` state field. For more flexible token flows, use `RunarContract` directly.

### Ordinals

#### `Inscription` ([src/ordinals/types.ts](src/ordinals/types.ts))

```typescript
interface Inscription {
  contentType: string;  // MIME type
  data: string;         // hex-encoded payload
}
```

#### `EnvelopeBounds` ([src/ordinals/types.ts](src/ordinals/types.ts))

```typescript
interface EnvelopeBounds {
  startHex: number;  // hex-char offset of OP_FALSE
  endHex: number;    // hex-char offset after OP_ENDIF
}
```

#### `buildInscriptionEnvelope` ([src/ordinals/envelope.ts](src/ordinals/envelope.ts))

```typescript
buildInscriptionEnvelope(contentType: string, data: string): string
```

Returns the envelope hex: `OP_FALSE OP_IF "ord" OP_1 <pushContentType> OP_0 <pushData> OP_ENDIF`.

#### `parseInscriptionEnvelope` ([src/ordinals/envelope.ts](src/ordinals/envelope.ts))

```typescript
parseInscriptionEnvelope(scriptHex: string): Inscription | null
```

Returns `null` if no envelope is present.

#### `findInscriptionEnvelope` ([src/ordinals/envelope.ts](src/ordinals/envelope.ts))

```typescript
findInscriptionEnvelope(scriptHex: string): EnvelopeBounds | null
```

Locates the envelope's hex-char bounds within a larger script.

#### `stripInscriptionEnvelope` ([src/ordinals/envelope.ts](src/ordinals/envelope.ts))

```typescript
stripInscriptionEnvelope(scriptHex: string): string
```

Returns the script with any envelope removed.

#### `BSV20` / `BSV21` ([src/ordinals/bsv20.ts](src/ordinals/bsv20.ts))

```typescript
BSV20.deploy({ tick, max, lim?, dec? }): Inscription
BSV20.mint({ tick, amt }): Inscription
BSV20.transfer({ tick, amt }): Inscription

BSV21.deployMint({ amt, dec?, sym?, icon? }): Inscription
BSV21.transfer({ id, amt }): Inscription
```

Build standard BSV-20 (tick-based) and BSV-21 (ID-based) inscriptions for fungible tokens. Use with `RunarContract.withInscription(...)` to attach to a contract.

### ANF interpreter

#### `computeNewState` ([src/anf-interpreter.ts](src/anf-interpreter.ts))

```typescript
computeNewState(
  anf: ANFProgram,
  methodName: string,
  currentState: Record<string, unknown>,
  args: Record<string, unknown>,
  constructorArgs?: unknown[],
): Record<string, unknown>
```

Walks the artifact's ANF IR for `methodName`, mutating a virtual state environment as the on-chain script would, and returns the resulting state. Skips on-chain-only operations (`check_preimage`, `check_sig`, `add_output`, etc.). Used internally by `call()` to auto-compute `newState`.

### Code generation

Available via the `runar-sdk/codegen` subpath import.

#### `generateTypescript(artifact)` ([src/codegen/gen-typescript.ts](src/codegen/gen-typescript.ts))

Returns a TypeScript module string defining a typed wrapper class around `RunarContract` for the given artifact. Hides auto-computed parameters, distinguishes terminal from state-mutating methods, and emits `prepareXxx` / `finalizeXxx` pairs for methods with `Sig` parameters.

#### `generateGo(artifact)`, `generateRust(artifact)`, `generatePython(artifact)`, `generateZig(artifact)` ([src/codegen/gen-all.ts](src/codegen/gen-all.ts))

Cross-target generators — render Mustache templates in `codegen/templates/wrapper.{go,rs,py,zig}.mustache` to produce typed bindings in the named language. Use these when one repo owns the contract and ships bindings to consumers in other languages.

#### `generateTypescriptFromTemplate(artifact)` ([src/codegen/gen-all.ts](src/codegen/gen-all.ts))

Template-based TypeScript generator (alternative to the imperative `generateTypescript`).

#### `classifyParams` / `getUserParams` / `getSdkArgParams` / `isTerminalMethod` / `isStatefulArtifact` / `getPublicMethods` / `safeMethodName` / `mapTypeToTS` / `mapTypeToGo` / `mapTypeToRust` / `mapTypeToPython` / `mapTypeToZig` / `buildCodegenContext` ([src/codegen/common.ts](src/codegen/common.ts))

Programmatic ABI-analysis helpers for building custom code generators.

#### `renderMustache(template, context)` ([src/codegen/mustache.ts](src/codegen/mustache.ts))

Minimal Mustache renderer used by the template-based generators. Exposed for projects that want to write their own templates against `buildCodegenContext` output.

### Types

```typescript
// Re-exported from runar-ir-schema
type RunarArtifact      // compiled contract metadata + script
type ABI                // method/constructor ABI
type ABIMethod          // single method ABI
type ABIParam           // method parameter
type ABIConstructor     // constructor ABI
type StateField         // single state field
type SourceMap          // optional debug source map
type SourceMapping      // single source-map entry

// SDK-defined
interface TransactionData { txid; version; inputs; outputs; locktime; raw? }
interface TxInput { txid; outputIndex; script; sequence }
interface TxOutput { satoshis; script }
interface UTXO { txid; outputIndex; satoshis; script }
interface DeployOptions { satoshis?; changeAddress? }
interface CallOptions { satoshis?; changeAddress?; changePubKey?; newState?; outputs?;
                        additionalContractInputs?; additionalContractInputArgs?;
                        terminalOutputs?; fundingUtxos?; dataOutputs? }
interface PreparedCall { sighash; preimage; opPushTxSig; tx; sigIndices; ... }

// Re-exported from @bsv/sdk
type Transaction        // @bsv/sdk Transaction class
```

---

## Error handling

The TypeScript SDK throws native `Error` objects with descriptive messages. There are no exported error classes; check `error.message` if you need to discriminate.

Common patterns:

```typescript
try {
  await contract.deploy({ satoshis: 1_000 });
} catch (err) {
  if (err instanceof Error && err.message.includes('no UTXOs found')) {
    // Fund the address and retry.
  } else if (err instanceof Error && err.message.includes('insufficient funds')) {
    // Increase funding or lower satoshis.
  } else {
    throw err;
  }
}
```

Frequently-encountered messages:

- `RunarContract: expected N constructor args for <Name>, got M` — from the constructor when arg count mismatches the ABI.
- `RunarContract.deploy: no UTXOs found for address <addr>` — provider returned an empty UTXO set.
- `buildDeployTransaction: insufficient funds. Need <X> sats, have <Y>` — funding inputs don't cover satoshis + fee.
- `RunarContract.prepareCall: contract is not deployed. Call deploy() or fromTxId() first.` — `currentUtxo` is `null`.
- `RunarContract.prepareCall: method '<name>' not found in <Name>` — method does not exist or is not public.
- `RunarContract.prepareCall: method '<name>' expects N args, got M` — user-arg count mismatch (excludes auto-injected params).
- `LocalSigner: expected a 64-char hex private key or a WIF-encoded key (starts with 5, K, or L)` — invalid `keyInput` to `LocalSigner`.
- `WoC broadcast failed (<status>): <body>` / `WoC getTransaction failed (...)` — HTTP errors from `WhatsOnChainProvider`.
- `RPC <method>: <message>` — JSON-RPC error from `RPCProvider`.
- `WalletProvider: ARC broadcast failed (<status>): <body>` — ARC rejected the transaction (frequently due to script-level failures).
- `WalletProvider: could not fetch parent tx <txid>` — EF assembly couldn't find a parent in cache or overlay.

For on-chain script-execution failures, the rejection message comes from the node and propagates through `provider.broadcast`. The `TestCounter_WrongStateHash_Rejected` and `TestCounter_DecrementFromZero_Rejected` cases in `integration/go/counter_test.go` (mirror tests exist in `integration/ts/counter.test.ts`) exercise these paths and assert `.rejects.toThrow()`.

---

## Troubleshooting / FAQ

**"contract is not deployed" on the second call.**
After a terminal method (one that does not produce a continuation output), `currentUtxo` is set to `null` deliberately. Reconnect with `RunarContract.fromTxId(...)` or `RunarContract.fromUtxo(...)` if you've created a new UTXO out of band.

**"hashOutputs mismatch" / network rejects a stateful call.**
Either you supplied an `options.newState` that doesn't match what the on-chain script expects, your `satoshis` for the continuation output is wrong, or the contract's data outputs (`this.addDataOutput(...)`) didn't match the SDK's emitted ones. The simplest fix is to omit `newState` so the SDK auto-derives it from the ANF IR.

**`WhatsOnChainProvider.getUtxos` returns UTXOs with empty `script`.**
This is a WoC API limitation. For deploy, the SDK doesn't need the source script — it signs against the provided one. If a downstream call needs it (e.g. for sighash computation against a non-P2PKH source), fetch the source transaction with `getTransaction(txid)` and read `outputs[outputIndex].script`.

**`RPCProvider.getContractUtxo()` always returns `null`.**
By design. Track the contract UTXO via `RunarContract.getUtxo()` after deploy/call, or query an indexer-backed provider.

**My WIF key is rejected with "expected a 64-char hex private key or a WIF-encoded key".**
WIF keys must start with `5`, `K`, or `L` (mainnet) and match the BSV WIF format. Testnet WIF (starts with `9` or `c`) is not auto-detected — convert to a 64-char hex private key first using `@bsv/sdk`'s `PrivateKey.fromWif(...).toHex()` or pass it through `PrivateKey.fromHex(...)` once you've decoded it.

**JSON-imported artifacts have `count: "0n"` strings instead of bigints.**
Bundlers like Vite serialize JSON without a custom reviver. The SDK's `RunarContract` constructor revives `bigint` initial values automatically by reading the artifact's type metadata. If you serialize state yourself, call `BigInt(value.replace(/n$/, ''))` on the suspect fields first.

**`MockProvider.getTransaction(txid)` throws after `broadcast`.**
`broadcast` records the raw hex but does not register a `TransactionData` entry. Pre-register via `mock.addTransaction({ txid, ... })`.

**Browser support.**
The SDK is ESM and uses native `fetch`. It runs in modern browsers when bundled. The `RPCProvider` (Node Buffer for basic auth) won't run unmodified in browsers — use `WalletProvider` or `WhatsOnChainProvider` instead, or polyfill `Buffer`.

**Async vs sync.**
All network and signing I/O is `async`. Even `MockProvider` returns Promises. Local transformations (`getLockingScript`, `buildUnlockingScript`, `state` getter, `setState`, `serializeState`, `deserializeState`, `selectUtxos`, `estimateDeployFee`, `estimateCallFee`, `computeOpPushTx`, `buildInscriptionEnvelope`) are synchronous.

---

## Versioning and stability

The SDK follows semver. Pre-1.0 minor versions may include breaking changes; check the changelog when upgrading.

`RunarContract`, `Provider`, `Signer`, `LocalSigner`, `ExternalSigner`, `WalletSigner`, `MockProvider`, `WhatsOnChainProvider`, `GorillaPoolProvider`, `RPCProvider`, `WalletProvider`, `serializeState`, `deserializeState`, `extractStateFromScript`, `findLastOpReturn`, `computeOpPushTx`, `buildP2PKHScript`, `selectUtxos`, `estimateDeployFee`, `estimateCallFee`, `buildDeployTransaction`, `buildCallTransaction`, the ordinals helpers, and the codegen subpath are part of the stable public surface.

The `_`-prefixed fields on `PreparedCall` are explicitly internal — `prepareCall` and `finalizeCall` round-trip them; do not depend on their shape.

The cross-SDK `conformance/sdk-output/` suite verifies that the TypeScript SDK produces byte-identical locking scripts to the Go, Rust, Python, Zig, Ruby, and Java SDKs for the same artifact + constructor args. As of this writing, 27 fixtures pass on all seven SDKs.

---

## Links

- Project README: <https://github.com/icellan/runar/blob/main/README.md>
- Language and contract authoring guide: <https://runar.build>
- Hosted contract gallery and playground: <https://runar.run>
- Examples (TypeScript, Go, Rust, Python, Solidity-like, Move-style, Java, Ruby, Zig): <https://github.com/icellan/runar/tree/main/examples>
- Issues and discussions: <https://github.com/icellan/runar/issues>
