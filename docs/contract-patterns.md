# Contract Patterns

This guide walks through common smart contract patterns in Rúnar with complete code examples and explanations. Each pattern demonstrates a different capability of Bitcoin SV script, from simple spending conditions to stateful on-chain logic.

---

## Pay-to-Public-Key-Hash (P2PKH)

The simplest and most common Bitcoin contract. Funds can be spent by anyone who can produce a valid signature for the specified public key hash.

```typescript
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
```

**How it works:**

1. At deployment, `pubKeyHash` (a 20-byte address) is embedded in the locking script.
2. To spend, the unlocking script provides a signature and a public key.
3. The contract hashes the public key with `hash160` (SHA-256 then RIPEMD-160) and checks it matches the stored hash.
4. If the hash matches, it verifies the signature against the public key.

**Compiles to:** `OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`

This is exactly the standard P2PKH script that most Bitcoin wallets use.

---

## Multi-Party Escrow

An escrow contract where funds can be released to the seller or refunded to the buyer, with an arbiter who can authorize either action.

```typescript
import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';

class Escrow extends SmartContract {
  readonly buyer: PubKey;
  readonly seller: PubKey;
  readonly arbiter: PubKey;

  constructor(buyer: PubKey, seller: PubKey, arbiter: PubKey) {
    super(buyer, seller, arbiter);
    this.buyer = buyer;
    this.seller = seller;
    this.arbiter = arbiter;
  }

  public release(sig: Sig) {
    assert(checkSig(sig, this.seller) || checkSig(sig, this.arbiter));
  }

  public refund(sig: Sig) {
    assert(checkSig(sig, this.buyer) || checkSig(sig, this.arbiter));
  }
}
```

**How it works:**

- **`release`**: The seller can release funds to themselves, or the arbiter can authorize release. Either signature suffices.
- **`refund`**: The buyer can reclaim funds, or the arbiter can authorize a refund.
- The `||` operator is short-circuit evaluated: if the first `checkSig` succeeds, the second is not executed.

Because this contract has two public methods, the compiler generates a dispatch table. The unlocking script includes a method index (`0n` for `release`, `1n` for `refund`) in addition to the signature.

---

## Stateful Counter (OP_PUSH_TX)

A contract whose state persists across transactions. The counter can be incremented or decremented, and the updated value is carried to the next UTXO.

```typescript
import { StatefulSmartContract, assert } from 'runar-lang';

class Counter extends StatefulSmartContract {
  count: bigint; // non-readonly = stateful

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

**How it works:**

1. The `count` property is mutable (no `readonly`), making this a stateful contract.
2. Extending `StatefulSmartContract` tells the compiler to automatically handle the OP_PUSH_TX pattern. For every public method, the compiler injects a preimage check at entry.
3. `this.count++` / `this.count--` updates the in-memory state.
4. Because these methods mutate state, the compiler automatically appends a state continuation assertion at the end — it serializes the updated state, hashes it, and verifies the transaction output carries the new state forward.

**State lifecycle:**

```
Deploy:    UTXO with count=0
Increment: Spend UTXO, create new UTXO with count=1
Increment: Spend UTXO, create new UTXO with count=2
Decrement: Spend UTXO, create new UTXO with count=1
```

---

## Fungible Token (FT)

A simple fungible token where ownership can be transferred. The total supply is immutable; the owner is mutable state.

```typescript
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class FungibleToken extends StatefulSmartContract {
  owner: PubKey;           // stateful: current token owner
  balance: bigint;         // stateful: token balance in this UTXO
  readonly tokenId: ByteString; // immutable: token identifier

  constructor(owner: PubKey, balance: bigint, tokenId: ByteString) {
    super(owner, balance, tokenId);
    this.owner = owner;
    this.balance = balance;
    this.tokenId = tokenId;
  }

  // Split: 1 input → 2 outputs (recipient + change)
  public transfer(sig: Sig, to: PubKey, amount: bigint, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(amount > 0n);
    assert(amount <= this.balance);

    // addOutput(satoshis, owner, balance) — args match mutable props in order
    this.addOutput(outputSatoshis, to, amount);
    this.addOutput(outputSatoshis, this.owner, this.balance - amount);
  }

  // Simple send: 1 input → 1 output, full balance
  public send(sig: Sig, to: PubKey, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    this.addOutput(outputSatoshis, to, this.balance);
  }

  // Merge: N inputs → 1 output (each input calls this independently)
  public merge(sig: Sig, totalBalance: bigint, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(totalBalance >= this.balance);
    this.addOutput(outputSatoshis, this.owner, totalBalance);
  }
}
```

**How it works:**

1. Each UTXO tracks an `owner` and a `balance` — the number of tokens it holds.
2. **Split (transfer)**: The owner signs and specifies a recipient and amount. `addOutput` registers two outputs: one for the recipient with the transferred amount, and one for the sender with the remaining balance. The compiler verifies both outputs against the transaction's `hashOutputs`.
3. **Send**: Transfers the full balance to a new owner in a single output.
4. **Merge**: Multiple UTXOs can be combined. Each input independently verifies the same output (with `totalBalance`). Since all inputs check the same `hashOutputs`, they must agree — if any input lies about the total, the hash check fails.

The `tokenId` is `readonly` and baked into the locking script at deploy time.

---

## Non-Fungible Token (NFT)

An NFT with a unique token ID, metadata, and a burn function.

```typescript
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class SimpleNFT extends StatefulSmartContract {
  owner: PubKey;                   // stateful
  readonly tokenId: ByteString;    // immutable: unique identifier
  readonly metadata: ByteString;   // immutable: metadata URI/hash

  constructor(owner: PubKey, tokenId: ByteString, metadata: ByteString) {
    super(owner, tokenId, metadata);
    this.owner = owner;
    this.tokenId = tokenId;
    this.metadata = metadata;
  }

  public transfer(sig: Sig, newOwner: PubKey, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    // addOutput(satoshis, owner) — single mutable prop
    this.addOutput(outputSatoshis, newOwner);
  }

  public burn(sig: Sig) {
    assert(checkSig(sig, this.owner));
    // No addOutput and no state mutation = token destroyed
  }
}
```

**Key difference from FT:** The NFT has a single mutable property (`owner`), so `addOutput` takes just satoshis and the new owner. The `burn` method uses neither `addOutput` nor direct state mutation, so the compiler only injects the preimage check — no state continuation. The token ceases to exist.

---

## Oracle Integration (Rabin Signatures)

A contract that uses an external data feed (oracle) verified via Rabin signatures. This example only pays out if the oracle-attested price exceeds a threshold.

```typescript
import {
  SmartContract, assert, PubKey, Sig, ByteString,
  RabinSig, RabinPubKey, checkSig, verifyRabinSig, num2bin
} from 'runar-lang';

class OraclePriceFeed extends SmartContract {
  readonly oraclePubKey: RabinPubKey;
  readonly receiver: PubKey;

  constructor(oraclePubKey: RabinPubKey, receiver: PubKey) {
    super(oraclePubKey, receiver);
    this.oraclePubKey = oraclePubKey;
    this.receiver = receiver;
  }

  public settle(price: bigint, rabinSig: RabinSig, padding: ByteString, sig: Sig) {
    // Verify the oracle signed this price
    const msg = num2bin(price, 8n);
    assert(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));

    // Price must exceed threshold
    assert(price > 50000n);

    // Receiver must sign
    assert(checkSig(sig, this.receiver));
  }
}
```

**How it works:**

1. The oracle publishes a price along with a Rabin signature.
2. `num2bin(price, 8n)` encodes the price as an 8-byte little-endian byte string (the message that was signed).
3. `verifyRabinSig` checks the Rabin signature against the oracle's public key. This proves the oracle attested to this specific price.
4. The contract enforces a business rule: `price > 50000n`.
5. The receiver must also sign the transaction.

Rabin signatures are used instead of ECDSA for oracle data because they are simpler to verify in Script and can sign arbitrary messages without the complexities of sighash construction.

---

## Covenant Enforcement

Covenants restrict how a UTXO can be spent by inspecting the spending transaction itself. This vault contract enforces that the owner can only send to a pre-specified recipient and must send at least a minimum amount.

```typescript
import {
  SmartContract, assert, PubKey, Sig, Addr, SigHashPreimage,
  checkSig, checkPreimage
} from 'runar-lang';

class CovenantVault extends SmartContract {
  readonly owner: PubKey;
  readonly recipient: Addr;
  readonly minAmount: bigint;

  constructor(owner: PubKey, recipient: Addr, minAmount: bigint) {
    super(owner, recipient, minAmount);
    this.owner = owner;
    this.recipient = recipient;
    this.minAmount = minAmount;
  }

  public spend(sig: Sig, amount: bigint, txPreimage: SigHashPreimage) {
    assert(checkSig(sig, this.owner));
    assert(checkPreimage(txPreimage));
    assert(amount >= this.minAmount);
  }
}
```

**How it works:**

The `checkPreimage` call gives the contract access to transaction details. The contract can then enforce rules about the outputs -- for example, that a minimum amount goes to the designated recipient. The owner's signature proves authorization, but the covenant rules constrain what the owner can actually do.

---

## On-Chain Auction

A stateful auction where bidders can submit increasing bids, and the auctioneer closes the auction after a deadline.

```typescript
import {
  SmartContract, assert, PubKey, Sig, SigHashPreimage,
  checkSig, checkPreimage, hash256, extractOutputHash, extractLocktime
} from 'runar-lang';

class Auction extends SmartContract {
  readonly auctioneer: PubKey;
  highestBidder: PubKey;      // stateful
  highestBid: bigint;          // stateful
  readonly deadline: bigint;   // block height deadline

  constructor(auctioneer: PubKey, highestBidder: PubKey, highestBid: bigint, deadline: bigint) {
    super(auctioneer, highestBidder, highestBid, deadline);
    this.auctioneer = auctioneer;
    this.highestBidder = highestBidder;
    this.highestBid = highestBid;
    this.deadline = deadline;
  }

  public bid(bidder: PubKey, bidAmount: bigint, txPreimage: SigHashPreimage) {
    assert(checkPreimage(txPreimage));
    assert(bidAmount > this.highestBid);
    assert(extractLocktime(txPreimage) < this.deadline);
    this.highestBidder = bidder;
    this.highestBid = bidAmount;
    assert(hash256(this.getStateScript()) === extractOutputHash(txPreimage));
  }

  public close(sig: Sig, txPreimage: SigHashPreimage) {
    assert(checkPreimage(txPreimage));
    assert(checkSig(sig, this.auctioneer));
    assert(extractLocktime(txPreimage) >= this.deadline);
    // No state continuation -- auction is done
  }
}
```

**How it works:**

- **`bid`**: Anyone can bid. The bid must exceed the current highest bid. The `extractLocktime` check ensures the auction has not passed its deadline. State is updated with the new highest bidder and bid amount.
- **`close`**: Only the auctioneer can close. The locktime check ensures the deadline has passed. No state is propagated -- the auction UTXO is consumed, and the auctioneer receives the funds.

This pattern demonstrates combining multiple stateful fields, time-based conditions via locktime, and two distinct spending paths with different authorization rules.

---

## Pattern Summary

| Pattern | Stateful | Key Techniques |
|---------|----------|----------------|
| P2PKH | No | `hash160`, `checkSig` |
| Escrow | No | Multiple public methods, `\|\|` for multi-party auth |
| Counter | Yes | OP_PUSH_TX, `getStateScript`, `extractOutputHash` |
| Fungible Token | Yes | Owner transfer via state update |
| NFT | Yes | Transfer + burn (no state continuation) |
| Oracle | No | Rabin signatures, `verifyRabinSig`, `num2bin` |
| Covenant | No | `checkPreimage` for transaction introspection |
| Auction | Yes | Multiple stateful fields, locktime checks, two spending paths |
| PostQuantumWallet | No | `verifyWOTS` — WOTS+ one-time PQ signature (~10 KB script) |
| SPHINCSWallet | No | `verifySLHDSA_SHA2_128s` — SLH-DSA stateless PQ signature (~203 KB script) |
