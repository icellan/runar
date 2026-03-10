# Inductive Smart Contracts

Inductive smart contracts solve the chain verification problem on Bitcoin's UTXO model. When a stateful contract like a token passes through hundreds or thousands of transactions, how does a verifier know the entire chain — from genesis to the present — is legitimate? Without induction, they would need to replay every transaction from the beginning, an exponentially growing task.

`InductiveSmartContract` eliminates this by making each transaction verify its own parent. Since the parent also verified *its* parent, and so on back to genesis, the entire lineage is proven valid by mathematical induction. A verifier only needs to see two consecutive transactions to trust the full chain.

---

## The Three Contract Types

Rúnar provides three base classes, each building on the last:

| | SmartContract | StatefulSmartContract | InductiveSmartContract |
|---|---|---|---|
| **State** | Stateless — all properties `readonly` | Mutable properties carried in UTXO state | Same as Stateful + 3 internal chain fields |
| **Preimage** | None | Auto-injected `checkPreimage` at entry | Same |
| **State continuation** | None | Auto-verified at exit (hashOutputs) | Same |
| **Chain verification** | None | None | Full backward verification via partial SHA-256 |
| **Additional state** | None | None | `_genesisOutpoint`, `_parentOutpoint`, `_grandparentOutpoint` (108 bytes) |
| **Additional unlock data** | None | `txPreimage` | 4 partial SHA-256 params (161 bytes) + `txPreimage` |
| **Script overhead** | None | ~2 KB (OP_PUSH_TX) | ~50 KB (2× SHA-256 compression + verification) |
| **Use case** | One-shot scripts (P2PKH, escrow) | Counters, vaults, any persistent state | Tokens, assets, provenance — anything requiring lineage proof |

**Key insight**: `InductiveSmartContract` extends `StatefulSmartContract`. The developer writes the same code — the compiler injects the chain verification machinery automatically. The ~50 KB script overhead comes from two inline SHA-256 compression rounds (~23 KB each) needed to verify the parent transaction's hash on-chain.

---

## The Problem: Chain Verification in UTXO Tokens

Consider a fungible token contract using `StatefulSmartContract`. It tracks an `owner` and `balance`, and each transfer creates a new UTXO carrying the updated state:

```
Genesis → Tx₁ → Tx₂ → Tx₃ → ... → Txₙ
```

At Txₙ, how does anyone know this token is real? A `StatefulSmartContract` enforces that each transition is valid (the owner signed, the balance is correct, the state is carried forward), but it says nothing about the *origin*. An attacker could create a counterfeit genesis with fake balances and produce a perfectly valid chain from that point.

The naive solution — check every transaction back to genesis — doesn't scale. At depth 1000, you need 1000 transaction lookups. At depth 1,000,000, you need 1,000,000. The verification cost grows linearly with chain length.

## The Solution: Backward Verification by Induction

The insight is borrowed from mathematical induction:

1. **Base case**: The genesis transaction is valid by definition (it creates the token).
2. **Inductive step**: If transaction Txₖ is valid, and Txₖ₊₁ correctly verifies Txₖ, then Txₖ₊₁ is also valid.

By encoding this logic directly into the Bitcoin script, every transaction in the chain carries its own proof of lineage. The verification cost is constant — O(1) — regardless of chain depth.

Each inductive transaction performs three checks:

1. **Parent authenticity**: The SDK computes a partial SHA-256 hash of the parent transaction, leaving the last 2 blocks (128 bytes) uncompressed. The contract completes the hash on-chain using `sha256Compress` and verifies the result matches the parent txid embedded in the current transaction's outpoint. This proves the provided data is genuinely from the parent transaction.

2. **Lineage consistency**: The contract extracts the parent's internal state fields from the uncompressed tail blocks and verifies that the parent's genesis outpoint matches its own. Two UTXOs with the same genesis outpoint belong to the same lineage.

3. **Chain linking**: The contract verifies that the parent's recorded parent-outpoint matches its own grandparent-outpoint. This ensures the chain of back-references is consistent — no links have been forged or skipped.

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

This is the same code you would write for a `StatefulSmartContract` token. The developer never sees or manages the inductive verification fields — they are entirely compiler-managed.

The contract is also available in all supported formats:

**Solidity-like** (`InductiveToken.runar.sol`):
```solidity
contract InductiveToken is InductiveSmartContract {
    PubKey owner;
    int balance;
    readonly ByteString tokenId;

    function transfer(Sig sig, PubKey to, int amount, int outputSatoshis) public {
        assert(checkSig(sig, owner));
        assert(amount > 0);
        assert(amount <= balance);
        addOutput(outputSatoshis, to, amount);
        addOutput(outputSatoshis, owner, balance - amount);
    }
}
```

**Go** (`InductiveToken.runar.go`):
```go
type InductiveToken struct {
    runar.InductiveSmartContract
    Owner   runar.PubKey
    Balance runar.Int
    TokenId runar.ByteString `runar:"readonly"`
}

func (c *InductiveToken) Transfer(sig runar.Sig, to runar.PubKey, amount runar.Int, outputSatoshis runar.Int) {
    runar.Assert(runar.CheckSig(sig, c.Owner))
    runar.Assert(amount > 0)
    runar.Assert(amount <= c.Balance)
    c.AddOutput(outputSatoshis, to, amount)
    c.AddOutput(outputSatoshis, c.Owner, c.Balance-amount)
}
```

**Rust** (`InductiveToken.runar.rs`):
```rust
#[runar::inductive_contract]
struct InductiveToken {
    owner: PubKey,
    balance: Int,
    #[readonly]
    token_id: ByteString,
}

#[runar::methods(InductiveToken)]
impl InductiveToken {
    #[public]
    fn transfer(&mut self, sig: Sig, to: PubKey, amount: Int, output_satoshis: Int) {
        assert!(check_sig(sig, self.owner));
        assert!(amount > 0);
        assert!(amount <= self.balance);
        self.add_output(output_satoshis, to, amount);
        self.add_output(output_satoshis, self.owner, self.balance - amount);
    }
}
```

**Python** (`InductiveToken.runar.py`):
```python
from runar import InductiveSmartContract, PubKey, Sig, ByteString, Bigint, Readonly, public, assert_

class InductiveToken(InductiveSmartContract):
    owner: PubKey
    balance: Bigint
    token_id: Readonly[ByteString]

    def __init__(self, owner: PubKey, balance: Bigint, token_id: ByteString):
        super().__init__(owner, balance, token_id)
        self.owner = owner
        self.balance = balance
        self.token_id = token_id

    @public
    def transfer(self, sig: Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint):
        assert_(check_sig(sig, self.owner))
        assert_(amount > 0)
        assert_(amount <= self.balance)
        self.add_output(output_satoshis, to, amount)
        self.add_output(output_satoshis, self.owner, self.balance - amount)
```

---

## What the Compiler Does

The compiler transforms the simple developer code above into a script that performs full inductive chain verification. Here is exactly what gets injected.

### Auto-Injected Internal State Fields

Three mutable `ByteString` properties are appended to the contract's property list, after all developer-declared properties:

| Field | Type | Size | Purpose |
|-------|------|------|---------|
| `_genesisOutpoint` | ByteString | 36 bytes | Immutable identity of the token lineage (txid + vout of the first UTXO) |
| `_parentOutpoint` | ByteString | 36 bytes | Outpoint of the parent UTXO that created this one |
| `_grandparentOutpoint` | ByteString | 36 bytes | Outpoint of the grandparent UTXO (parent's parent) |

These fields are invisible to the developer. They participate in state serialization automatically, appearing as the last entries in the OP_RETURN state data.

### Auto-Injected Implicit Parameters

Five implicit parameters are appended to every public method's parameter list:

| Parameter | Type | Size | Purpose |
|-----------|------|------|---------|
| `_parentHashState` | ByteString | 32 bytes | SHA-256 intermediate state covering all blocks of the parent tx before the tail |
| `_parentTailBlock1` | ByteString | 64 bytes | First uncompressed SHA-256 tail block (contains end of parent tx data) |
| `_parentTailBlock2` | ByteString | 64 bytes | Second tail block (contains SHA-256 padding + bit length) |
| `_parentRawTailLen` | bigint | ~1 byte | Number of raw tx bytes in the 128-byte tail (used to compute field extraction offset) |
| `txPreimage` | SigHashPreimage | ~varies | BIP-143 sighash preimage (same as StatefulSmartContract) |

The SDK computes all of these automatically — the developer does not need to supply them.

### Parent Transaction Verification: Partial SHA-256

Instead of passing the full raw parent transaction (which would cause exponential growth as each child embeds its parent), the SDK pre-hashes most of the parent transaction and passes only the last 128 bytes of uncompressed data. The contract completes the hash on-chain:

```
mid        = sha256Compress(_parentHashState, _parentTailBlock1)
singleHash = sha256Compress(mid, _parentTailBlock2)
parentTxId = sha256(singleHash)    // double-SHA256 for Bitcoin txid
assert(parentTxId === left(extractOutpoint(txPreimage), 32))
```

This proves the provided tail data and hash state are genuinely from the parent transaction. The total data passed is constant (161 bytes) regardless of parent transaction size.

Each `sha256Compress` call inlines ~23 KB of SHA-256 compression opcodes (64 rounds of bit manipulation using OP_LSHIFT, OP_RSHIFT, OP_AND, OP_XOR, etc.). This is why inductive contracts add ~50 KB to the script size.

### Method Entry: Verification Sequence

The following verification logic is injected at the beginning of every public method, before the developer's code runs:

```
Step 1: Check preimage (OP_PUSH_TX)
    assert(checkPreimage(txPreimage))

Step 2: Verify parent transaction via partial SHA-256
    mid        = sha256Compress(_parentHashState, _parentTailBlock1)
    singleHash = sha256Compress(mid, _parentTailBlock2)
    parentTxId = sha256(singleHash)
    assert(parentTxId === left(extractOutpoint(txPreimage), 32))

Step 3: Genesis detection and chain verification
    if (_genesisOutpoint === 0x0000...0000₃₆) {
        // GENESIS: First spend of the token.
        // The all-zeros sentinel is an impossible real outpoint, so it
        // unambiguously signals that genesis identity has not been set yet.
        _genesisOutpoint = extractOutpoint(txPreimage)
    } else {
        // NON-GENESIS: Extract internal fields from the SHA-256 tail blocks.
        // The tail blocks contain the end of the parent tx data (outputs + locktime).
        // Internal fields are the last 111 bytes before locktime:
        //   3 fields * (1 push opcode + 36 data bytes) = 111 bytes
        tailData = cat(_parentTailBlock1, _parentTailBlock2)
        fieldStart = _parentRawTailLen - 4 - 111  // before locktime, before fields
        internalFields = mid(tailData, fieldStart, 111)

        parentGenesis        = extract bytes [1..37)   // skip push opcode
        parentParentOutpoint = extract bytes [38..74)   // skip push opcode

        assert(parentGenesis === _genesisOutpoint)            // same lineage
        assert(parentParentOutpoint === _grandparentOutpoint)  // chain links match
    }
```

### Between Entry and Exit: Field Updates

After the verification sequence and before the developer's method body executes, the chain-linking fields are updated:

```
_grandparentOutpoint = _parentOutpoint           // shift one generation back
_parentOutpoint = extractOutpoint(txPreimage)     // current tx becomes the new parent
// _genesisOutpoint is unchanged (immutable after genesis)
```

This ordering matters: the developer's `addOutput()` calls need the *updated* internal field values, so the fields must be updated before the developer body runs. When `addOutput()` is called, the compiler automatically appends load references for `_genesisOutpoint`, `_parentOutpoint`, and `_grandparentOutpoint` to the output's state values.

### Method Exit: State Continuation

After the developer's code, the same state continuation mechanism as `StatefulSmartContract` runs:

- If the method uses `addOutput()`: the serialized outputs are concatenated, hashed, and compared against `extractOutputHash(txPreimage)`.
- If the method has no explicit `addOutput()`: the full state script (including internal fields) is hashed and compared against `extractOutputHash(txPreimage)`.

---

## Genesis Detection: The Zero Sentinel

The genesis detection mechanism uses a 36-byte all-zeros value as a sentinel for `_genesisOutpoint`. This works because:

1. A real Bitcoin outpoint is 32 bytes of txid + 4 bytes of output index.
2. A txid of all zeros (`0x00...00₃₂`) is the hash of no valid transaction.
3. Therefore, a 36-byte all-zeros value can never be a real outpoint.

When the contract is first deployed, `_genesisOutpoint` is initialized to `0x00...00₃₆`. On the first spend (genesis), the contract detects this sentinel and sets `_genesisOutpoint` to the current transaction's outpoint — permanently establishing the token's identity. All subsequent spends take the non-genesis path and verify chain consistency.

---

## Extracting Internal Fields from Tail Blocks

The parent's internal fields are extracted from the SHA-256 tail blocks at a known offset. The tail blocks contain the last 128 bytes of the raw parent transaction data (plus SHA-256 padding). Since a Bitcoin transaction always ends with `[...outputs...][locktime(4 bytes)]`, and the internal fields are always the last entries in the output script's state section, they sit at a predictable position relative to the end of the raw data.

The SDK passes `_parentRawTailLen` to tell the contract how many of the 128 tail bytes are actual transaction data (the rest is SHA-256 padding). The extraction is:

```
fieldStart = _parentRawTailLen - 4 (locktime) - 111 (internal fields)
internalFields = tailData[fieldStart .. fieldStart + 111]
```

The internal field layout within those 111 bytes is fixed:
- Bytes `[0..37)`: push opcode (0x24) + `_genesisOutpoint` (36 bytes)
- Bytes `[37..74)`: push opcode (0x24) + `_parentOutpoint` (36 bytes)
- Bytes `[74..111)`: push opcode (0x24) + `_grandparentOutpoint` (36 bytes)

Each field is extracted by skipping the 1-byte push opcode prefix before the 36-byte data value. This approach is robust to changes in developer properties or code script length — it only depends on the fixed internal field layout at the end.

---

## Transaction Flow Example

Here is how an inductive token flows through its lifecycle:

### Deploy (Genesis)

```
Tx₀ (funding tx):
  Output[0]: [covenant script] OP_RETURN [owner] [balance] [tokenId]
                                          [0x00..00₃₆] [0x00..00₃₆] [0x00..00₃₆]
                                           ↑ genesis     ↑ parent      ↑ grandparent
                                           (sentinel)    (sentinel)    (sentinel)
```

### First Spend (Genesis Detection)

```
Tx₁ (first transfer):
  Input[0]:  [sig, newOwner, amount, sats, _parentHashState, _tailBlock1, _tailBlock2, _rawTailLen, txPreimage]
  Output[0]: [covenant script] OP_RETURN [newOwner] [amount] [tokenId]
                                          [outpoint(Tx₁)]   [outpoint(Tx₁)]  [0x00..00₃₆]
                                           ↑ genesis set!    ↑ parent=self    ↑ grandparent
```

During Tx₁, `_genesisOutpoint` is the zero sentinel, so the genesis branch runs:
- `_genesisOutpoint` is set to `extractOutpoint(txPreimage)` — the identity of Tx₁.
- `_grandparentOutpoint` = old `_parentOutpoint` = `0x00..00₃₆`
- `_parentOutpoint` = `extractOutpoint(txPreimage)` = outpoint of Tx₁

### Subsequent Spends (Chain Verification)

```
Tx₂ (second transfer):
  Input[0]:  [sig, newOwner, amount, sats, _parentHashState, _tailBlock1, _tailBlock2, _rawTailLen, txPreimage]

  Verification:
    1. sha256(sha256Compress(sha256Compress(state, block1), block2))
       === left(extractOutpoint(preimage), 32)          ✓ parent data is genuine
    2. Extract Tx₁'s internal fields from tail blocks:
       - Tx₁._genesisOutpoint  === my._genesisOutpoint    ✓ same lineage
       - Tx₁._parentOutpoint   === my._grandparentOutpoint ✓ chain links

  Output[0]: [covenant script] OP_RETURN [newOwner] [amount] [tokenId]
                                          [outpoint(Tx₁)]     [outpoint(Tx₂)]    [outpoint(Tx₁)]
                                           ↑ genesis (same)    ↑ parent=Tx₂       ↑ grandparent=Tx₁
```

At every step, the chain is verified backward one link. Since Tx₂ verified Tx₁, and Tx₁ established genesis, the entire chain from genesis to Tx₂ is proven valid. This property holds inductively for any chain length.

---

## SDK Integration

The deployment SDKs (TypeScript, Go, Rust, Python) automatically handle the inductive implicit parameters:

1. When calling a method on an inductive contract, the SDK detects the `_parentHashState` parameter in the contract's ABI.
2. It fetches the raw parent transaction from the blockchain provider using the current UTXO's txid.
3. It computes the partial SHA-256 split: pre-hashing all blocks except the last 2, returning the intermediate state + 2 tail blocks + raw tail length.
4. The 4 parameters are included in the unlocking script, pushed before `txPreimage`.

No developer action is required — the SDK computes and provides everything transparently.

```typescript
// SDK usage is identical to StatefulSmartContract
const token = new RunarContract(artifact, constructorArgs);
token.connect(signer, provider);

// The SDK computes partial SHA-256 automatically
await token.call('transfer', [sig, newOwner, amount, satoshis]);
```

---

## Comparison with StatefulSmartContract

| Feature | StatefulSmartContract | InductiveSmartContract |
|---------|----------------------|----------------------|
| State persistence | OP_PUSH_TX + state continuation | Same |
| Chain verification | None | Full backward verification via partial SHA-256 |
| Additional state fields | None | 3 internal fields (108 bytes of data) |
| Additional unlocking data | txPreimage | 4 partial SHA-256 params (161 bytes) + txPreimage |
| Script size overhead | ~2 KB | ~50 KB (2× SHA-256 compression + verification logic) |
| Verification cost | O(1) per tx | O(1) per tx, O(1) total chain verification |
| Unlocking data growth | Constant | Constant (161 bytes regardless of chain depth) |
| Use case | Simple stateful contracts | Tokens, assets, anything requiring provenance |

---

## Script Size Budget

| Component | Size |
|-----------|------|
| `sha256Compress` × 2 (verify parent txid) | ~46 KB |
| `sha256()` (double-hash for txid) | 1 byte |
| Lineage verification (genesis check, chain links) | ~1 KB |
| Field extraction from tail blocks | ~0.5 KB |
| `checkPreimage` (OP_PUSH_TX) | ~2 KB |
| State continuation (`addOutput` + hashOutputs) | ~2-3 KB |
| Developer method body | varies |

Typical inductive token: ~52-55 KB. Fits comfortably within BSV's unlimited script size.

---

## Formal Verification

The induction argument underlying `InductiveSmartContract` is simple enough to be machine-checked. The core theorem can be stated informally as:

> **Theorem (Chain Integrity).** For any UTXO chain `Tx₀, Tx₁, …, Txₙ` where every transaction satisfies the inductive verification predicate, there exists no index `k` such that `Txₖ` has a different genesis outpoint than `Tx₀`.

The proof follows directly from the two-branch structure of the verification logic:

1. **Base case (genesis).** When `_genesisOutpoint` is the zero sentinel, the contract sets it to the current outpoint. This is the only point at which `_genesisOutpoint` is written. The sentinel value `0x00…00₃₆` is not a valid outpoint, so no real transaction can trigger the genesis branch after this point.

2. **Inductive step (non-genesis).** The contract extracts the parent's `_genesisOutpoint` from the SHA-256-verified tail blocks and asserts it equals the current transaction's `_genesisOutpoint`. If the parent was valid (by the inductive hypothesis), its genesis outpoint traces back to the true genesis. The equality assertion forces the current transaction to share that lineage.

3. **Chain linking.** The grandparent consistency check (`parentParentOutpoint === _grandparentOutpoint`) prevents an attacker from splicing a valid suffix onto a forged prefix. Even if an attacker produces a parent with the correct genesis outpoint, the grandparent back-reference must also match — and that reference was set by the *genuine* chain, which the attacker cannot retroactively modify (Bitcoin transactions are immutable once confirmed).

This argument has three assumptions that would need to be axiomatized in a formal proof:

- **Hash collision resistance.** SHA-256 (and double SHA-256) is collision-resistant: no adversary can produce two distinct transactions with the same hash. This is the standard cryptographic assumption underlying all of Bitcoin.
- **Preimage binding.** `checkPreimage` correctly binds the sighash preimage to the spending transaction. This is guaranteed by the BIP-143 sighash algorithm and OP_PUSH_TX.
- **Script immutability.** The locking script (covenant) is identical across all UTXOs in the chain. This is enforced by the state continuation mechanism inherited from `StatefulSmartContract`, which hashes the output scripts and compares against `extractOutputHash`.

Given these axioms, the proof is a straightforward structural induction on chain length.
