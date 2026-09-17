import { StatefulSmartContract, assert, checkSig, hash256, substr, extractHashPrevouts, extractOutpoint } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

/**
 * FungibleToken -- A UTXO-based fungible token using Runar's multi-output (`addOutput`) facility.
 *
 * Demonstrates how to model divisible token balances that can be split, transferred, and
 * merged -- similar to colored coins or SLP-style tokens but enforced entirely by Bitcoin Script.
 *
 * **UTXO token model vs account model:**
 * Unlike Ethereum ERC-20 where balances live in a global mapping, each token "balance" here
 * is a separate UTXO. The UTXO carries state: the current owner (PubKey), balance (bigint),
 * and an immutable tokenId (ByteString). Transferring tokens means spending one UTXO and
 * creating new ones with updated state.
 *
 * **Operations:**
 * - `transfer` -- Split: 1 UTXO -> 2 UTXOs (recipient + change back to sender)
 * - `send`     -- Simple send: 1 UTXO -> 1 UTXO (full balance to new owner)
 * - `merge`    -- Merge: 2 UTXOs -> 1 UTXO (UNSOUND: does not authenticate a second token input; W8 / SoloMerge)
 *
 * **UNSOUND merge (W8 / SoloMerge):** `merge` never asserts that a second token
 * covenant is an input of the spending transaction. `hash256(allPrevouts) ===
 * extractHashPrevouts(preimage)` only proves `allPrevouts` is the real prevout
 * list. A one-input spend takes the "I am input 0" arm and writes the
 * spender-chosen `otherBalance` into the successor. A P2PKH fee input filling
 * `len(allPrevouts) === 72` does not close the hole. Pin:
 * `packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts`.
 * For a construction that binds a specific companion input, see
 * `examples/ts/companion-verifier/`.
 *
 * The output stores both individual balances (`balance` and `mergeBalance`) so they can
 * be independently verified. Subsequent operations use the sum as the available balance.
 *
 * **Authorization:** All operations require the current owner's ECDSA signature via `checkSig`.
 */
class FungibleToken extends StatefulSmartContract {
  /** Current owner's public key. Mutable -- updated when tokens are sent to a new owner. */
  owner: PubKey;
  /** Primary token balance. Mutable -- adjusted on transfer/split/merge. */
  balance: bigint;
  /** Secondary balance slot used during merge for cross-input verification. Normally 0. */
  mergeBalance: bigint;
  /**
   * Unique token identifier. Readonly -- baked into the locking script at deploy time
   * and cannot change, ensuring token identity is preserved across all transfers.
   */
  readonly tokenId: ByteString;

  constructor(owner: PubKey, balance: bigint, mergeBalance: bigint, tokenId: ByteString) {
    super(owner, balance, mergeBalance, tokenId);
    this.owner = owner;
    this.balance = balance;
    this.mergeBalance = mergeBalance;
    this.tokenId = tokenId;
  }

  /**
   * Transfer tokens to a recipient. If the full balance is sent, produces 1 output;
   * otherwise produces 2 outputs (recipient + change back to sender).
   */
  public transfer(sig: Sig, to: PubKey, amount: bigint, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    const totalBalance = this.balance + this.mergeBalance;
    assert(amount > 0n);
    assert(amount <= totalBalance);

    this.addOutput(outputSatoshis, to, amount, 0n);
    if (amount < totalBalance) {
      this.addOutput(outputSatoshis, this.owner, totalBalance - amount, 0n);
    }
  }

  /**
   * Simple send: 1 UTXO -> 1 UTXO. Transfers the entire balance to a new owner.
   */
  public send(sig: Sig, to: PubKey, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);

    this.addOutput(outputSatoshis, to, this.balance + this.mergeBalance, 0n);
  }

  /**
   * Merge: 2 UTXOs -> 1 UTXO. Consolidates two token UTXOs.
   *
   * **UNSOUND (W8 / SoloMerge):** this method does not authenticate a second
   * token input. The position-dependent slot construction below is the
   * intended two-input argument; its premise (a second input running this
   * covenant) is never checked. A one-input spend writes `otherBalance` into
   * the successor. Pin:
   * `packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts`.
   *
   * What the script actually does, *if* two token inputs happen to be present:
   * each input writes its own locking-script balance to a slot based on
   * whether its outpoint is first in `allPrevouts`, and `hashOutputs` then
   * forces those two inputs to agree. That is not a proof that a second
   * token input exists.
   *
   * @param sig            - Current owner's signature
   * @param otherBalance   - Claimed balance of the other merging input
   * @param allPrevouts    - Concatenated outpoints of all tx inputs (verified via hashPrevouts)
   * @param outputSatoshis - Satoshis to fund the merged output
   */
  public merge(sig: Sig, otherBalance: bigint, allPrevouts: ByteString, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    assert(otherBalance >= 0n);

    // Verify allPrevouts is authentic (matches the actual transaction inputs)
    assert(hash256(allPrevouts) === extractHashPrevouts(this.txPreimage));

    // Determine position: am I the first contract input?
    const myOutpoint = extractOutpoint(this.txPreimage);
    const firstOutpoint = substr(allPrevouts, 0n, 36n);
    const myBalance = this.balance + this.mergeBalance;

    if (myOutpoint === firstOutpoint) {
      // I'm input 0: my verified balance goes to slot 0
      this.addOutput(outputSatoshis, this.owner, myBalance, otherBalance);
    } else {
      // I'm input 1: my verified balance goes to slot 1
      this.addOutput(outputSatoshis, this.owner, otherBalance, myBalance);
    }
  }
}
