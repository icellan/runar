# Inductive Smart Contracts

Inductive smart contracts solve the chain verification problem on Bitcoin's UTXO model. When a stateful contract like a token passes through hundreds or thousands of transactions, how does a verifier know the entire chain — from genesis to the present — is legitimate? Without induction, they would need to replay every transaction from the beginning, an exponentially growing task.

`InductiveSmartContract` eliminates this by making each transaction verify its own parent. Since the parent also verified *its* parent, and so on back to genesis, the entire lineage is proven valid by mathematical induction. A verifier only needs to see two consecutive transactions to trust the full chain.

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

1. **Parent authenticity**: The raw parent transaction is provided in the unlocking script. The contract hashes it and verifies the hash matches the parent txid embedded in the current transaction's outpoint. This proves the provided parent tx bytes are genuine.

2. **Lineage consistency**: The contract extracts the parent's state from its output script and verifies that the parent's genesis outpoint matches its own. Two UTXOs with the same genesis outpoint belong to the same lineage.

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
#[runar::contract]
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

Two implicit parameters are appended to every public method's parameter list:

| Parameter | Type | Purpose |
|-----------|------|---------|
| `parentTx` | ByteString | Raw bytes of the parent transaction (provided by the SDK) |
| `txPreimage` | SigHashPreimage | BIP-143 sighash preimage (same as StatefulSmartContract) |

The SDK fetches the raw parent transaction automatically when calling the contract — the developer does not need to supply it.

### Method Entry: Verification Sequence

The following verification logic is injected at the beginning of every public method, before the developer's code runs:

```
Step 1: Check preimage (OP_PUSH_TX)
    assert(checkPreimage(txPreimage))

Step 2: Verify parent transaction authenticity
    assert(hash256(parentTx) === left(extractOutpoint(txPreimage), 32))

    The outpoint embedded in the sighash preimage contains the parent txid
    (first 32 bytes) and the output index (last 4 bytes). By hashing the
    provided raw parent tx and comparing it to the txid from the outpoint,
    we prove the raw bytes are the genuine parent transaction.

Step 3: Genesis detection and chain verification
    if (_genesisOutpoint === 0x0000...0000₃₆) {
        // GENESIS: First spend of the token.
        // The all-zeros sentinel is an impossible real outpoint, so it
        // unambiguously signals that genesis identity has not been set yet.
        _genesisOutpoint = extractOutpoint(txPreimage)
    } else {
        // NON-GENESIS: Verify chain consistency.
        parentOutputScript = extractParentOutput(parentTx, 0)

        // Extract internal fields from the END of parent output script.
        // Internal fields are the last 111 bytes: 3 fields * (1 push opcode + 36 data bytes).
        // Field layout (from end of script):
        //   bytes [0..37):   push(36) + _genesisOutpoint
        //   bytes [37..74):  push(36) + _parentOutpoint
        //   bytes [74..111): push(36) + _grandparentOutpoint
        internalBytes = right(parentOutputScript, 111)
        parentGenesis         = extract bytes [1..37)    // skip push opcode
        parentParentOutpoint  = extract bytes [38..74)   // skip push opcode

        assert(parentGenesis === _genesisOutpoint)           // same lineage
        assert(parentParentOutpoint === _grandparentOutpoint) // chain links match
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

## Extracting the Parent Output Script

The `extract_parent_output` operation is a dedicated ANF IR node that compiles to approximately 30 Bitcoin Script opcodes. It parses the raw bytes of a Bitcoin transaction to extract the output script at a given index. The parsing involves:

1. Skip the 4-byte version field
2. Read the input count (varint)
3. For each input: skip 32 (txid) + 4 (vout) + varint (scriptSig length) + scriptSig + 4 (sequence)
4. Read the output count (varint)
5. Skip to the target output index
6. Skip the 8-byte satoshis field
7. Read the script length (varint)
8. Extract the script bytes

This is too complex to express as a chain of existing ANF builtins, which is why it has a dedicated IR node. The V1 implementation handles 1-byte varints (< 253 inputs/outputs), which covers 99%+ of real-world Bitcoin transactions.

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
  Input[0]:  [sig, newOwner, amount, sats, parentTx=Tx₀_raw, txPreimage]
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
  Input[0]:  [sig, newOwner, amount, sats, parentTx=Tx₁_raw, txPreimage]

  Verification:
    1. hash256(Tx₁_raw) === left(extractOutpoint(preimage), 32)  ✓ parent is genuine
    2. Extract Tx₁'s output script, read internal fields from end:
       - Tx₁._genesisOutpoint  === my._genesisOutpoint    ✓ same lineage
       - Tx₁._parentOutpoint   === my._grandparentOutpoint ✓ chain links

  Output[0]: [covenant script] OP_RETURN [newOwner] [amount] [tokenId]
                                          [outpoint(Tx₁)]     [outpoint(Tx₂)]    [outpoint(Tx₁)]
                                           ↑ genesis (same)    ↑ parent=Tx₂       ↑ grandparent=Tx₁
```

At every step, the chain is verified backward one link. Since Tx₂ verified Tx₁, and Tx₁ established genesis, the entire chain from genesis to Tx₂ is proven valid. This property holds inductively for any chain length.

---

## Fixed-Width Trailing Extraction

A key design choice is how the contract reads the parent's internal fields from its output script. Rather than parsing the full state structure (which would require knowing the code script length and developer property sizes), the contract uses **fixed-width trailing extraction**.

The internal fields are always the last entries in the state section. Their sizes are fixed:
- 1 byte push opcode (`0x24` = push 36 bytes) + 36 bytes data = 37 bytes per field
- 3 fields * 37 bytes = 111 bytes total

The extraction is simply:
```
internalBytes = right(parentOutputScript, 111)
```

Then each field is extracted by offset arithmetic, skipping the 1-byte push opcode prefix before each 36-byte value. This approach is robust to changes in developer properties or code script length — it only depends on the fixed internal field layout at the end.

---

## SDK Integration

The deployment SDKs (TypeScript, Go, Rust) automatically handle the `parentTx` implicit parameter:

1. When calling a method on an inductive contract, the SDK detects the `parentTx` parameter in the contract's ABI.
2. It fetches the raw parent transaction from the blockchain provider using the current UTXO's txid.
3. The raw bytes are included in the unlocking script, pushed before `txPreimage`.

No developer action is required — the SDK fetches and provides the parent transaction transparently.

```typescript
// SDK usage is identical to StatefulSmartContract
const token = new RunarContract(artifact, constructorArgs);
token.connect(signer, provider);

// The SDK fetches parentTx automatically
await token.call('transfer', [sig, newOwner, amount, satoshis]);
```

---

## Comparison with StatefulSmartContract

| Feature | StatefulSmartContract | InductiveSmartContract |
|---------|----------------------|----------------------|
| State persistence | OP_PUSH_TX + state continuation | Same |
| Chain verification | None | Full backward verification |
| Additional state fields | None | 3 internal fields (108 bytes of data) |
| Additional unlocking data | txPreimage | parentTx + txPreimage |
| Script size overhead | None | ~30 opcodes for tx parsing + verification logic |
| Verification cost | O(1) per tx | O(1) per tx, O(1) total chain verification |
| Use case | Simple stateful contracts | Tokens, assets, anything requiring provenance |

---

## Formal Verification

The induction argument underlying `InductiveSmartContract` is simple enough to be machine-checked. The core theorem can be stated informally as:

> **Theorem (Chain Integrity).** For any UTXO chain `Tx₀, Tx₁, …, Txₙ` where every transaction satisfies the inductive verification predicate, there exists no index `k` such that `Txₖ` has a different genesis outpoint than `Tx₀`.

The proof follows directly from the two-branch structure of the verification logic:

1. **Base case (genesis).** When `_genesisOutpoint` is the zero sentinel, the contract sets it to the current outpoint. This is the only point at which `_genesisOutpoint` is written. The sentinel value `0x00…00₃₆` is not a valid outpoint, so no real transaction can trigger the genesis branch after this point.

2. **Inductive step (non-genesis).** The contract extracts the parent's `_genesisOutpoint` from its output script and asserts it equals the current transaction's `_genesisOutpoint`. If the parent was valid (by the inductive hypothesis), its genesis outpoint traces back to the true genesis. The equality assertion forces the current transaction to share that lineage.

3. **Chain linking.** The grandparent consistency check (`parentParentOutpoint === _grandparentOutpoint`) prevents an attacker from splicing a valid suffix onto a forged prefix. Even if an attacker produces a parent with the correct genesis outpoint, the grandparent back-reference must also match — and that reference was set by the *genuine* chain, which the attacker cannot retroactively modify (Bitcoin transactions are immutable once confirmed).

This argument has three assumptions that would need to be axiomatized in a formal proof:

- **Hash collision resistance.** `hash256` (double SHA-256) is collision-resistant: no adversary can produce two distinct transactions with the same hash. This is the standard cryptographic assumption underlying all of Bitcoin.
- **Preimage binding.** `checkPreimage` correctly binds the sighash preimage to the spending transaction. This is guaranteed by the BIP-143 sighash algorithm and OP_PUSH_TX.
- **Script immutability.** The locking script (covenant) is identical across all UTXOs in the chain. This is enforced by the state continuation mechanism inherited from `StatefulSmartContract`, which hashes the output scripts and compares against `extractOutputHash`.

Given these axioms, the proof is a straightforward structural induction on chain length. A Coq or Lean formalization would likely be under 200 lines, consisting of:

- A record type for the UTXO state (genesis, parent, grandparent outpoints)
- A predicate for the verification check (the if/else logic)
- A transition function for the field updates
- The induction theorem with a `nat_ind` proof term

The simplicity of the invariant — "every transaction in the chain shares the same genesis outpoint, and the back-reference chain is consistent" — is by design. More complex verification schemes might offer additional guarantees, but they would sacrifice the ability to reason about correctness with confidence.

---

## Limitations (V1)

- **1-byte varint only**: The transaction parser handles inputs/outputs counts up to 252. Transactions with 253+ inputs or outputs are not supported. This covers 99%+ of real transactions.
- **Fixed 36-byte outpoints**: The internal field sizes are hardcoded. This is a fundamental Bitcoin constant (32-byte txid + 4-byte vout) and is unlikely to change.
