# Inductive Smart Contracts

Inductive smart contracts extend stateful contracts with automatic genesis tracking. `InductiveSmartContract` adds a `_genesisOutpoint` field that immutably identifies the token lineage, and a `_proof` field reserved for future ZKP-based backward chain verification.

---

## The Three Contract Types

Rúnar provides three base classes, each building on the last:

| | SmartContract | StatefulSmartContract | InductiveSmartContract |
|---|---|---|---|
| **State** | Stateless — all properties `readonly` | Mutable properties carried in UTXO state | Same as Stateful + 2 internal fields |
| **Preimage** | None | Auto-injected `checkPreimage` at entry | Same |
| **State continuation** | None | Auto-verified at exit (hashOutputs) | Same |
| **Genesis tracking** | None | None | Auto-injected genesis outpoint detection |
| **Additional state** | None | None | `_genesisOutpoint` (36 bytes), `_proof` (192 bytes) |
| **Additional unlock data** | None | `txPreimage` | Same as Stateful |
| **Use case** | One-shot scripts (P2PKH, escrow) | Counters, vaults, any persistent state | Tokens, assets — anything requiring lineage identity |

**Key insight**: `InductiveSmartContract` extends `StatefulSmartContract`. The developer writes the same code — the compiler injects genesis tracking automatically.

---

## Developer Experience

From the developer's perspective, writing an inductive contract is identical to writing a stateful contract. You extend `InductiveSmartContract` instead of `StatefulSmartContract`, and the compiler handles everything else:

```typescript
import { InductiveSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class InductiveToken extends InductiveSmartContract {
  owner: PubKey;
  balance: bigint;
  readonly tokenId: ByteString;

  constructor(owner: PubKey, balance: bigint, tokenId: ByteString) {
    super(owner, balance, tokenId);
    this.owner = owner;
    this.balance = balance;
    this.tokenId = tokenId;
  }

  public transfer(sig: Sig, to: PubKey, amount: bigint, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(amount > 0n);
    assert(amount <= this.balance);

    this.addOutput(outputSatoshis, to, amount);
    this.addOutput(outputSatoshis, this.owner, this.balance - amount);
  }

  public send(sig: Sig, to: PubKey, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    this.addOutput(outputSatoshis, to, this.balance);
  }
}
```

This is the same code you would write for a `StatefulSmartContract` token. The developer never sees or manages the internal fields — they are entirely compiler-managed.

---

## What the Compiler Does

The compiler transforms the developer code above into a script with genesis tracking. Here is exactly what gets injected.

### Auto-Injected Internal State Fields

Two mutable `ByteString` properties are appended to the contract's property list, after all developer-declared properties:

| Field | Type | Size | Purpose |
|-------|------|------|---------|
| `_genesisOutpoint` | ByteString | 36 bytes | Immutable identity of the token lineage (txid + vout of the first UTXO) |
| `_proof` | ByteString | 192 bytes | ZKP proof placeholder (stub — future SNARK verifier) |

These fields are invisible to the developer. They participate in state serialization automatically, appearing as the last entries in the OP_RETURN state data.

### Auto-Injected Implicit Parameters

The same implicit parameters as `StatefulSmartContract`:

| Parameter | Type | Size | Condition | Purpose |
|-----------|------|------|-----------|---------|
| `_changePKH` | Ripemd160 | 20 bytes | If method mutates state or uses `addOutput` | Change output recipient |
| `_changeAmount` | bigint | ~varies | If method mutates state or uses `addOutput` | Satoshis for the change output |
| `_newAmount` | bigint | ~varies | If method mutates state (single-output only) | Satoshis for the continuation UTXO |
| `txPreimage` | SigHashPreimage | ~varies | Always | BIP-143 sighash preimage |

### Method Entry: Genesis Detection

The following logic is injected at the beginning of every public method:

```
Step 1: Check preimage (OP_PUSH_TX)
    assert(checkPreimage(txPreimage))

Step 2: Deserialize state from preimage's scriptCode

Step 3: Genesis detection
    if (_genesisOutpoint === ZERO_SENTINEL) {
        // First spend — set genesis to current outpoint
        _genesisOutpoint = extractOutpoint(txPreimage)
    }
    // Non-genesis: _genesisOutpoint is preserved unchanged

Step 4: Developer's method body runs

Step 5: State continuation (hashOutputs verification)
```

The genesis detection uses a 36-byte zero sentinel. On the first spend after deployment, `_genesisOutpoint` is set to the outpoint being spent. On subsequent spends, it is preserved unchanged. This gives each token lineage a unique, immutable identity.

### Output Ordering

Same as `StatefulSmartContract`: covenant outputs first, change output last.

---

## SDK Usage

The SDK handles inductive contracts transparently:

```typescript
const artifact = compile(source, { fileName: 'InductiveToken.runar.ts' });
const contract = new RunarContract(artifact, [
  ownerPubKey,
  1000n,
  tokenIdHex,
  '00'.repeat(36),    // _genesisOutpoint (zero sentinel)
  '00'.repeat(192),   // _proof (zero placeholder)
]);

await contract.deploy(provider, signer, { satoshis: 500_000 });

// First spend — genesis detection sets _genesisOutpoint
await contract.call('send', [null, recipientPubKey, 1n], provider, signer, {
  newState: { owner: recipientPubKey },
  satoshis: 1,
});

// Subsequent spends — _genesisOutpoint preserved
await contract.call('send', [null, nextPubKey, 1n], provider, signer, {
  newState: { owner: nextPubKey },
  satoshis: 1,
});
```

The SDK automatically updates `_genesisOutpoint` in the state when building continuation outputs, matching what the on-chain script computes.

---

## Future: ZKP-Based Chain Verification

The `_proof` field is a 192-byte placeholder for a future recursive SNARK proof. When implemented, the SNARK verifier will be injected into the locking script, replacing the genesis-only detection with full backward chain verification:

- The proof attests to the validity of the entire chain from genesis to the current transaction
- Supports both linear chains and DAG topologies (enabling token merges)
- Constant verification cost regardless of chain depth
- The `_genesisOutpoint` serves as a public input to the SNARK circuit
