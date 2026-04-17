# 1sat Ordinals & BSV-20/BSV-21 Tokens

This guide covers how to use Rúnar smart contracts with 1sat ordinals — inscribing NFTs, deploying BSV-20 fungible tokens, and working with BSV-21 tokens. All 6 SDKs (TypeScript, Go, Rust, Python, Zig, Ruby) support ordinals through the same API surface.

---

## How 1sat Ordinals Work

1sat ordinals inscribe data into Bitcoin SV outputs using a protocol envelope — a no-op script fragment that carries content without affecting transaction execution:

```
OP_FALSE OP_IF
  PUSH "ord"       ← protocol identifier
  OP_1              ← version
  PUSH <mime-type>  ← content type (e.g. "image/png", "application/bsv-20")
  OP_0              ← delimiter
  PUSH <data>       ← inscription content
OP_ENDIF
```

The `OP_FALSE OP_IF ... OP_ENDIF` block is never executed — the `OP_FALSE` causes the `OP_IF` to skip. The data is preserved on-chain in the output's locking script, visible to indexers.

### Script Structure in Rúnar

Rúnar places the inscription envelope **after** the compiled contract code and **before** any state data:

```
Stateless:  [compiled_script] [inscription_envelope]
Stateful:   [compiled_code]   [inscription_envelope] OP_RETURN <state>
```

For stateful contracts, the inscription becomes part of the codePart — it persists identically across all state transitions. The existing `findLastOpReturn()` opcode walker correctly skips the envelope and finds the real OP_RETURN at the code/state boundary.

### Immutable Inscriptions

Inscriptions in Rúnar are **immutable**. Once deployed, the inscription is part of the contract's on-chain identity and cannot be changed. For stateful contracts, the on-chain `hashOutputs` verification naturally includes the inscription in every continuation output.

To transfer an NFT to a new owner, use a terminal method that spends the UTXO and creates new outputs.

---

## Quick Start

### Deploy an NFT with an Inscription

Write a standard Rúnar contract — the inscription is attached at deployment time via the SDK, not in the contract source.

**Contract (any format):**

<table>
<tr><td>

**TypeScript** (`OrdinalNFT.runar.ts`)
```typescript
import { SmartContract, assert, Sig, PubKey,
  Addr, hash160, checkSig } from 'runar-lang';

class OrdinalNFT extends SmartContract {
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
</td><td>

**Go** (`OrdinalNFT.runar.go`)
```go
type OrdinalNFT struct {
    runar.SmartContract
    PubKeyHash runar.Addr `runar:"readonly"`
}

func (c *OrdinalNFT) Unlock(
    sig runar.Sig, pubKey runar.PubKey) {
    runar.Assert(
        runar.Hash160(pubKey) == c.PubKeyHash)
    runar.Assert(runar.CheckSig(sig, pubKey))
}
```
</td></tr>
<tr><td>

**Rust** (`OrdinalNFT.runar.rs`)
```rust
#[runar::contract]
pub struct OrdinalNFT {
    #[readonly]
    pub pub_key_hash: Addr,
}

#[runar::methods(OrdinalNFT)]
impl OrdinalNFT {
    #[public]
    pub fn unlock(&self, sig: &Sig,
        pub_key: &PubKey) {
        assert!(hash160(pub_key)
            == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}
```
</td><td>

**Python** (`OrdinalNFT.runar.py`)
```python
from runar import (SmartContract, Addr,
    PubKey, Sig, hash160, check_sig,
    assert_, public)

class OrdinalNFT(SmartContract):
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig,
        pub_key: PubKey):
        assert_(hash160(pub_key)
            == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
```
</td></tr>
<tr><td>

**Ruby** (`OrdinalNFT.runar.rb`)
```ruby
class OrdinalNFT < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end
```
</td><td>

**Zig** (`OrdinalNFT.runar.zig`)
```zig
const runar = @import("runar");

pub const OrdinalNFT = struct {
    pub const Contract = runar.SmartContract;
    pub_key_hash: runar.Addr,

    pub fn init(pkh: runar.Addr) OrdinalNFT {
        return .{ .pub_key_hash = pkh };
    }

    pub fn unlock(self: *const OrdinalNFT,
        sig: runar.Sig,
        pub_key: runar.PubKey) void {
        runar.assert(runar.hash160(pub_key)
            == self.pub_key_hash);
        runar.assert(
            runar.checkSig(sig, pub_key));
    }
};
```
</td></tr>
</table>

**Deploy with inscription (all 6 SDKs):**

<table>
<tr><td>

**TypeScript**
```typescript
import { RunarContract } from 'runar-sdk';

const contract = new RunarContract(artifact, [pubKeyHash]);
contract.withInscription({
  contentType: 'image/png',
  data: pngHexData,
});
await contract.deploy(provider, signer, { satoshis: 1 });
```
</td><td>

**Go**
```go
contract := runar.NewRunarContract(&artifact, args)
contract.WithInscription(&runar.Inscription{
    ContentType: "image/png",
    Data:        pngHexData,
})
contract.Deploy(provider, signer,
    runar.DeployOptions{Satoshis: 1})
```
</td></tr>
<tr><td>

**Rust**
```rust
let mut contract = RunarContract::new(artifact, args);
contract.with_inscription(Inscription {
    content_type: "image/png".into(),
    data: png_hex_data.into(),
});
contract.deploy(&mut provider, &signer,
    DeployOptions { satoshis: 1, .. })?;
```
</td><td>

**Python**
```python
from runar.sdk import RunarContract
from runar.sdk.ordinals import Inscription

contract = RunarContract(artifact, [pub_key_hash])
contract.with_inscription(Inscription(
    content_type="image/png",
    data=png_hex_data,
))
contract.deploy(provider, signer, satoshis=1)
```
</td></tr>
<tr><td>

**Ruby**
```ruby
contract = Runar::SDK::RunarContract.new(
  artifact, [pub_key_hash])
contract.with_inscription(
  Runar::SDK::Inscription.new(
    content_type: "image/png",
    data: png_hex_data))
contract.deploy(provider, signer, satoshis: 1)
```
</td><td>

**Zig**
```zig
var contract = try RunarContract.init(
    allocator, &artifact, args);
contract.withInscription(.{
    .content_type = "image/png",
    .data = png_hex_data,
});
try contract.deploy(provider, signer, .{
    .satoshis = 1,
});
```
</td></tr>
</table>

---

## BSV-20 Fungible Tokens

BSV-20 is a tick-based fungible token standard. Tokens are JSON inscriptions on 1-sat UTXOs with content type `application/bsv-20`.

### Token Lifecycle

1. **Deploy** — register a new ticker with max supply and optional mint limit
2. **Mint** — create tokens up to the per-mint limit
3. **Transfer** — move tokens between UTXOs

### Deploy a BSV-20 Token

```typescript
import { RunarContract, BSV20 } from 'runar-sdk';

const contract = new RunarContract(artifact, [pubKeyHash]);
contract.withInscription(BSV20.deploy({
  tick: 'RUNAR',       // 4+ character ticker (first-is-first)
  max: '21000000',     // maximum supply
  lim: '1000',         // per-mint limit (optional)
  dec: '8',            // decimal precision (optional, max 18)
}));
await contract.deploy(provider, signer, { satoshis: 1 });
```

This inscribes:
```json
{"p":"bsv-20","op":"deploy","tick":"RUNAR","max":"21000000","lim":"1000","dec":"8"}
```

### Mint Tokens

```typescript
const mintContract = new RunarContract(artifact, [pubKeyHash]);
mintContract.withInscription(BSV20.mint({
  tick: 'RUNAR',
  amt: '1000',
}));
await mintContract.deploy(provider, signer, { satoshis: 1 });
```

Each mint creates a new 1-sat UTXO. The `amt` must not exceed the `lim` set during deploy.

### Transfer Tokens

```typescript
const transferContract = new RunarContract(artifact, [recipientPubKeyHash]);
transferContract.withInscription(BSV20.transfer({
  tick: 'RUNAR',
  amt: '50',
}));
await transferContract.deploy(provider, signer, { satoshis: 1 });
```

Transfers move tokens by spending the source UTXO and creating new UTXOs with transfer inscriptions. Unallocated tokens (inputs > outputs) are burned.

### BSV-20 in Other Languages

<table>
<tr><td>

**Go**
```go
insc := runar.BSV20Deploy("RUNAR", "21000000",
    ptr("1000"), ptr("8"))
contract.WithInscription(insc)

mint := runar.BSV20Mint("RUNAR", "1000")
transfer := runar.BSV20Transfer("RUNAR", "50")
```
</td><td>

**Rust**
```rust
let insc = bsv20_deploy("RUNAR", "21000000",
    Some("1000"), Some("8"));
contract.with_inscription(insc);

let mint = bsv20_mint("RUNAR", "1000");
let transfer = bsv20_transfer("RUNAR", "50");
```
</td></tr>
<tr><td>

**Python**
```python
from runar.sdk.ordinals import (
    bsv20_deploy, bsv20_mint, bsv20_transfer)

insc = bsv20_deploy("RUNAR", "21000000",
    lim="1000", dec="8")
contract.with_inscription(insc)

mint = bsv20_mint("RUNAR", "1000")
transfer = bsv20_transfer("RUNAR", "50")
```
</td><td>

**Ruby**
```ruby
insc = Runar::SDK::Ordinals.bsv20_deploy(
    tick: "RUNAR", max: "21000000",
    lim: "1000", dec: "8")
contract.with_inscription(insc)

mint = Runar::SDK::Ordinals.bsv20_mint(
    tick: "RUNAR", amt: "1000")
transfer = Runar::SDK::Ordinals.bsv20_transfer(
    tick: "RUNAR", amt: "50")
```
</td></tr>
</table>

---

## BSV-21 Tokens (ID-Based)

BSV-21 tokens combine deploy and mint in a single operation. Instead of a ticker, each token is identified by its origin `txid_vout`. This allows admin-controlled distribution without the "first-is-first" ticker race.

### Deploy + Mint

```typescript
import { RunarContract, BSV21 } from 'runar-sdk';

const contract = new RunarContract(artifact, [pubKeyHash]);
contract.withInscription(BSV21.deployMint({
  amt: '1000000',      // total supply
  dec: '18',            // decimal precision (optional)
  sym: 'RNR',           // ticker symbol (optional, display only)
  icon: 'https://...',  // icon URL (optional)
}));
const { txid } = await contract.deploy(provider, signer, { satoshis: 1 });

// Token ID is txid_vout of the inscription output
const tokenId = `${txid}_0`;
```

### Transfer BSV-21

```typescript
const transferContract = new RunarContract(artifact, [recipientPubKeyHash]);
transferContract.withInscription(BSV21.transfer({
  id: tokenId,    // the txid_vout from deploy
  amt: '100',
}));
await transferContract.deploy(provider, signer, { satoshis: 1 });
```

### BSV-21 in Other Languages

<table>
<tr><td>

**Go**
```go
insc := runar.BSV21DeployMint("1000000",
    ptr("18"), ptr("RNR"), nil)
contract.WithInscription(insc)

transfer := runar.BSV21Transfer(tokenId, "100")
```
</td><td>

**Rust**
```rust
let insc = bsv21_deploy_mint("1000000",
    Some("18"), Some("RNR"), None);
contract.with_inscription(insc);

let transfer = bsv21_transfer(&token_id, "100");
```
</td></tr>
<tr><td>

**Python**
```python
from runar.sdk.ordinals import (
    bsv21_deploy_mint, bsv21_transfer)

insc = bsv21_deploy_mint("1000000",
    dec="18", sym="RNR")
contract.with_inscription(insc)

transfer = bsv21_transfer(token_id, "100")
```
</td><td>

**Ruby**
```ruby
insc = Runar::SDK::Ordinals.bsv21_deploy_mint(
    amt: "1000000", dec: "18", sym: "RNR")
contract.with_inscription(insc)

transfer = Runar::SDK::Ordinals.bsv21_transfer(
    id: token_id, amt: "100")
```
</td></tr>
</table>

---

## Advanced: Ordinals with Complex Contracts

The real power of Rúnar ordinals is combining inscriptions with contracts that go beyond P2PKH. Any Rúnar contract — stateless or stateful — can carry an inscription.

### Escrow-Locked NFT

Lock an NFT in escrow that requires either buyer+seller agreement or arbiter intervention:

```typescript
import { SmartContract, assert, PubKey, Sig, Addr,
  hash160, checkSig } from 'runar-lang';

class EscrowNFT extends SmartContract {
  readonly seller: Addr;
  readonly buyer: Addr;
  readonly arbiter: Addr;

  constructor(seller: Addr, buyer: Addr, arbiter: Addr) {
    super(seller, buyer, arbiter);
    this.seller = seller;
    this.buyer = buyer;
    this.arbiter = arbiter;
  }

  // Buyer and seller agree — release to buyer
  public release(sellerSig: Sig, sellerPub: PubKey,
                 buyerSig: Sig, buyerPub: PubKey) {
    assert(hash160(sellerPub) === this.seller);
    assert(checkSig(sellerSig, sellerPub));
    assert(hash160(buyerPub) === this.buyer);
    assert(checkSig(buyerSig, buyerPub));
  }

  // Arbiter resolves dispute
  public arbitrate(arbiterSig: Sig, arbiterPub: PubKey) {
    assert(hash160(arbiterPub) === this.arbiter);
    assert(checkSig(arbiterSig, arbiterPub));
  }
}
```

Deploy with an image inscription:

```typescript
const escrow = new RunarContract(artifact, [sellerHash, buyerHash, arbiterHash]);
escrow.withInscription({
  contentType: 'image/png',
  data: artworkPngHex,
});
await escrow.deploy(provider, signer, { satoshis: 1 });
```

The NFT is locked in escrow — it can only be released (transferred) when both parties agree or the arbiter intervenes.

### Stateful Counter with Inscription

Inscriptions work with stateful contracts. The inscription persists across all state transitions:

```typescript
import { StatefulSmartContract, assert } from 'runar-lang';

class InscribedCounter extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment() {
    this.count++;
  }
}
```

```typescript
const counter = new RunarContract(artifact, [0n]);
counter.withInscription({
  contentType: 'application/json',
  data: Buffer.from(JSON.stringify({
    name: 'Ordinal Counter #1',
    description: 'A counter that lives as a 1sat ordinal',
  })).toString('hex'),
});
await counter.deploy(provider, signer, { satoshis: 1 });

// Every state transition preserves the inscription
await counter.call('increment', [], provider, signer);
// counter.inscription is still available after reconnecting
const reconnected = await RunarContract.fromTxId(artifact, txid, 0, provider);
console.log(reconnected.inscription.contentType); // "application/json"
console.log(reconnected.state.count);             // 1n
```

### Token Contract with Built-in Transfer Logic

Combine BSV-20 inscriptions with a custom token contract that enforces transfer rules on-chain:

```typescript
import { StatefulSmartContract, assert, PubKey, Sig,
  Addr, hash160, checkSig } from 'runar-lang';

class GuardedToken extends StatefulSmartContract {
  holder: PubKey;
  readonly minHoldBlocks: bigint;

  constructor(holder: PubKey, minHoldBlocks: bigint) {
    super(holder, minHoldBlocks);
    this.holder = holder;
    this.minHoldBlocks = minHoldBlocks;
  }

  // Transfer only if the holder signs
  public transfer(sig: Sig, newHolder: PubKey) {
    assert(checkSig(sig, this.holder));
    this.holder = newHolder;
  }
}
```

```typescript
const token = new RunarContract(artifact, [holderPubKey, 100n]);
token.withInscription(BSV20.deploy({
  tick: 'LOCK',
  max: '1000000',
}));
await token.deploy(provider, signer, { satoshis: 1 });
```

This creates a BSV-20 token whose UTXO is guarded by on-chain transfer logic — the holder must sign to transfer, and the contract state tracks the current holder across transactions.

---

## Reconnecting to Inscribed Contracts

When you reconnect to an on-chain contract via `fromTxId` or `fromUtxo`, the SDK automatically detects and parses any inscription in the locking script:

```typescript
const contract = await RunarContract.fromTxId(artifact, txid, 0, provider);

if (contract.inscription) {
  console.log(contract.inscription.contentType); // e.g. "image/png"
  console.log(contract.inscription.data);        // hex-encoded content
}
```

The inscription is preserved in `_codeScript` — it is **not** stripped. This ensures stateful contracts produce correct continuation outputs.

---

## Envelope Utilities

The SDK exports low-level envelope functions for advanced use cases:

```typescript
import {
  buildInscriptionEnvelope,   // (contentType, data) → hex
  parseInscriptionEnvelope,   // (scriptHex) → Inscription | null
  findInscriptionEnvelope,    // (scriptHex) → EnvelopeBounds | null
  stripInscriptionEnvelope,   // (scriptHex) → hex (bare script)
} from 'runar-sdk';

// Build an envelope manually
const envelopeHex = buildInscriptionEnvelope('text/plain', '48656c6c6f');

// Parse an envelope from any script
const inscription = parseInscriptionEnvelope(someLockingScript);

// Find the envelope's byte boundaries
const bounds = findInscriptionEnvelope(someLockingScript);

// Remove the envelope to get the bare contract script
const bareScript = stripInscriptionEnvelope(someLockingScript);
```

These functions are available in all 6 SDKs with equivalent signatures.

---

## GorillaPool Provider

The `GorillaPoolProvider` implements the standard `Provider` interface and adds ordinal-specific query methods. It connects to the [1sat Ordinals](https://1satordinals.com/) indexer.

```typescript
import { GorillaPoolProvider } from 'runar-sdk';

const provider = new GorillaPoolProvider('mainnet');
// or: new GorillaPoolProvider('testnet')

// Standard Provider methods work as usual
const tx = await provider.getTransaction(txid);
const utxos = await provider.getUtxos(address);

// Ordinal-specific methods
const inscriptions = await provider.getInscriptionsByAddress(address);
const detail = await provider.getInscription('txid_0');
const balance = await provider.getBSV20Balance(address, 'RUNAR');
const tokenUtxos = await provider.getBSV20Utxos(address, 'RUNAR');
const bsv21Balance = await provider.getBSV21Balance(address, tokenId);
```

The provider is available in all 6 SDKs:
- **TypeScript**: `GorillaPoolProvider` from `runar-sdk`
- **Go**: `runar.NewGorillaPoolProvider("mainnet")`
- **Rust**: `GorillaPoolProvider::new("mainnet")`
- **Python**: `GorillaPoolProvider("mainnet")`
- **Zig**: `GorillaPoolProvider.init(allocator, .mainnet)`
- **Ruby**: `Runar::SDK::GorillaPoolProvider.new("mainnet")`

---

## Examples

Working example contracts and tests are in the repository:

| Example | Description | Location |
|---------|-------------|----------|
| Ordinal NFT | P2PKH-locked NFT with image inscription | [`examples/ts/ordinal-nft/`](../examples/ts/ordinal-nft/) |
| BSV-20 Token | BSV-20 deploy/mint/transfer flow | [`examples/ts/bsv20-token/`](../examples/ts/bsv20-token/) |
| BSV-21 Token | BSV-21 deploy+mint/transfer flow | [`examples/ts/bsv21-token/`](../examples/ts/bsv21-token/) |

Integration tests (on-chain regtest) are in [`integration/ts/`](../integration/ts/):
- `ordinal-nft.test.ts` — deploy, round-trip, spend, large inscription
- `bsv20-token.test.ts` — deploy, mint, transfer + spend
- `bsv21-token.test.ts` — deploy+mint, transfer, spend
